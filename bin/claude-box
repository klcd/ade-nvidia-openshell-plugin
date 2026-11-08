#!/usr/bin/env python3
"""
OpenShell Dynamic Sandbox Bridge for Claude Code (claude-box)

Features:
- Dynamically discovers project workspace root.
- Merges global policies (~/.agents/policies/) and project policies (<project>/.agents/policies/).
- Applies Landlock policy directly during sandbox creation (--policy) in <1 second.
- Fast paths for version/help to host claude.
- Retrieves and stages Claude OAuth credentials from host macOS Keychain or environment.
- Stages ~/.claude and ~/.claude.json inside container (preserving workspace trust, settings, skills).
- Automatic teardown: downloads workspace modifications back to host and deletes the container on exit.
"""

import sys
import os
import subprocess
import threading
import json
import time
import re
import signal
import shutil
import glob

DEBUG_LOG = os.path.expanduser("~/.claude/openshell-bridge.log")

def find_host_binary(name="claude"):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            try:
                real = os.path.realpath(candidate)
                if not (real.endswith("-bridge.py") or real.endswith("-box")):
                    return candidate
            except Exception:
                pass
    user = os.environ.get("USER", "")
    for fallback in [
        f"/etc/profiles/per-user/{user}/bin/{name}",
        f"/run/current-system/sw/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}"
    ]:
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback
    return None

REAL_CLAUDE = find_host_binary("claude")

def log_debug(msg):
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [PID {os.getpid()}] {msg}\n")
    except Exception:
        pass

def get_claude_oauth_token():
    # 1. Environment variable if already set
    for env_var in ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]:
        val = os.environ.get(env_var)
        if val:
            return val

    # 2. macOS Keychain lookup for "Claude Code-credentials"
    if sys.platform == "darwin":
        try:
            res = subprocess.run(
                ["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            if res.returncode == 0 and res.stdout.strip():
                try:
                    data = json.loads(res.stdout.strip())
                    token = data.get("claudeAiOauth", {}).get("accessToken")
                    if token:
                        return token
                except Exception:
                    pass
        except Exception:
            pass

    return None

def detect_project_root():
    cwd = os.getcwd()
    try:
        res = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return cwd

def load_policy_file(path):
    if not os.path.exists(path):
        return None
    try:
        if path.endswith(".json"):
            with open(path) as f:
                return json.load(f)
        elif path.endswith(".yaml") or path.endswith(".yml"):
            try:
                import yaml
                with open(path) as f:
                    return yaml.safe_load(f)
            except ImportError:
                res = subprocess.run(["yq", ".", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode == 0:
                    return json.loads(res.stdout)
    except Exception as e:
        log_debug(f"Failed to parse policy {path}: {e}")
    return None

def merge_policies(policy_dirs):
    merged = {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": "read_write",
            "read_only": [],
            "read_write": []
        },
        "landlock": {
            "compatibility": "best_effort"
        },
        "network_policies": {}
    }
    seen_ro = set()
    seen_rw = set()
    found_any = False

    for pdir in policy_dirs:
        if not os.path.isdir(pdir):
            continue
        for fpath in sorted(glob.glob(os.path.join(pdir, "*"))):
            if not (fpath.endswith(".json") or fpath.endswith(".yaml") or fpath.endswith(".yml")):
                continue
            try:
                data = load_policy_file(fpath)
                if not data or not isinstance(data, dict):
                    continue
                found_any = True
                fsp = data.get("filesystem_policy", {})
                if "include_workdir" in fsp:
                    merged["filesystem_policy"]["include_workdir"] = fsp["include_workdir"]
                for p in fsp.get("read_only", []):
                    if p not in seen_ro:
                        seen_ro.add(p)
                        merged["filesystem_policy"]["read_only"].append(p)
                for p in fsp.get("read_write", []):
                    if p not in seen_rw:
                        seen_rw.add(p)
                        merged["filesystem_policy"]["read_write"].append(p)
                
                ll = data.get("landlock", {})
                merged["landlock"].update(ll)
                
                np = data.get("network_policies", {})
                if isinstance(np, dict):
                    for k, v in np.items():
                        if not k.startswith("_provider_"):
                            merged["network_policies"][k] = v
            except Exception as e:
                log_debug(f"Failed to load policy {fpath}: {e}")
    if not found_any:
        return None
    return merged

def main():
    args = sys.argv[1:]
    cwd = os.getcwd()

    # Fast paths: help or version
    for arg in args:
        if arg in ("--version", "-V", "--help", "-h"):
            if REAL_CLAUDE:
                os.execv(REAL_CLAUDE, [REAL_CLAUDE] + args)

    proj_root = detect_project_root()
    proj_name = os.path.basename(proj_root)
    safe_proj = re.sub(r'[^a-zA-Z0-9_-]', '-', proj_name).lower()
    pid = os.getpid()

    # OpenShell sandbox names must be <= 19 characters
    sandbox_name = f"cc-{safe_proj[:8].strip('-')}-{pid % 100000}"
    log_debug(f"Starting session for {proj_name} (sandbox {sandbox_name}), args={args}")

    # Discover & merge policies
    global_policies = os.path.expanduser("~/.agents/policies")
    proj_policies = os.path.join(proj_root, ".agents", "policies")
    merged_policy = merge_policies([global_policies, proj_policies])

    p_tmp = f"/tmp/policy-claude-{pid}.json"
    create_cmd = [
        "openshell", "sandbox", "create",
        "--name", sandbox_name,
        "--from", "openshell-claude:latest",
        "--provider", "claude-code",
        "--provider", "github",
        "--detach"
    ]
    if merged_policy:
        with open(p_tmp, "w") as f:
            json.dump(merged_policy, f)
        create_cmd.extend(["--policy", p_tmp])

    try:
        subprocess.run(create_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log_debug(f"Failed to create sandbox: {e}.")
        if os.path.exists(p_tmp):
            try: os.remove(p_tmp)
            except Exception: pass
        if REAL_CLAUDE:
            log_debug("Falling back to host claude.")
            os.execv(REAL_CLAUDE, [REAL_CLAUDE] + args)
        else:
            sys.exit(1)

    if os.path.exists(p_tmp):
        try: os.remove(p_tmp)
        except Exception: pass

    cleanup_done = False
    cleanup_lock = threading.Lock()

    def cleanup():
        nonlocal cleanup_done
        with cleanup_lock:
            if cleanup_done:
                return
            cleanup_done = True
            log_debug(f"Cleaning up {sandbox_name}")
            try:
                # Sync back settings, history, or session files to host
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, "/sandbox/.claude/history.jsonl", os.path.expanduser("~/.claude/history.jsonl")],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass
            try:
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, f"/sandbox/{proj_name}", proj_root],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                log_debug(f"Download error: {e}")

            try:
                subprocess.run(
                    ["openshell", "sandbox", "delete", sandbox_name],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                log_debug(f"Delete error: {e}")

    def signal_handler(signum, frame):
        cleanup()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal_handler)

    try:
        # Stage ~/.claude, ~/.claude.json, and ~/.gitconfig
        stage_dir = f"/tmp/claude-stage-{pid}"
        os.makedirs(f"{stage_dir}/.claude", exist_ok=True)

        # Copy essential ~/.claude files
        host_claude = os.path.expanduser("~/.claude")
        if os.path.isdir(host_claude):
            for item in ["settings.json", "keybindings.json", "skills", "plugins"]:
                src = os.path.join(host_claude, item)
                dst = os.path.join(stage_dir, ".claude", item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                elif os.path.isfile(src):
                    shutil.copy(src, dst)

        # Combine user-level global skills (~/.claude/skills precedence over ~/.agents/skills)
        host_agents_skills = os.path.expanduser("~/.agents/skills")
        staged_claude_skills = os.path.join(stage_dir, ".claude", "skills")
        if os.path.isdir(host_agents_skills):
            os.makedirs(staged_claude_skills, exist_ok=True)
            for entry in os.listdir(host_agents_skills):
                target_skill = os.path.join(staged_claude_skills, entry)
                if not os.path.exists(target_skill):
                    source_skill = os.path.join(host_agents_skills, entry)
                    if os.path.isdir(source_skill):
                        shutil.copytree(source_skill, target_skill, dirs_exist_ok=True)
                    else:
                        shutil.copy(source_skill, target_skill)

        # Stage ~/.claude.json with trust for container workspace paths
        host_claude_json = os.path.expanduser("~/.claude.json")
        claude_config = {}
        if os.path.isfile(host_claude_json):
            try:
                with open(host_claude_json) as f:
                    claude_config = json.load(f)
            except Exception:
                pass

        projects = claude_config.setdefault("projects", {})
        for p in ["/sandbox", f"/sandbox/{proj_name}", proj_root]:
            proj_entry = projects.setdefault(p, {})
            proj_entry["hasTrustDialogAccepted"] = True

        claude_config["hasCompletedOnboarding"] = True

        with open(f"{stage_dir}/.claude.json", "w") as f:
            json.dump(claude_config, f, indent=2)

        with open(f"{stage_dir}/.gitconfig", "w") as f:
            f.write("[safe]\n\tdirectory = *\n")

        # Stage configs into container
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.claude", "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.claude.json", "/sandbox/.claude.json"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.gitconfig", "/sandbox/.gitconfig"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(stage_dir, ignore_errors=True)

        # Upload project workspace
        subprocess.run(["openshell", "sandbox", "upload", "--no-git-ignore", sandbox_name, proj_root, "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Prepare execution environment
        oauth_token = get_claude_oauth_token()
        cmd = [
            "openshell", "sandbox", "exec",
            "--name", sandbox_name,
            "--workdir", f"/sandbox/{proj_name}",
            "--tty"
        ]
        if oauth_token:
            cmd.extend(["--env", f"CLAUDE_CODE_OAUTH_TOKEN={oauth_token}"])

        cmd.extend(["--", "claude"] + args)

        old_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            proc = subprocess.Popen(cmd)
            proc.wait()
        finally:
            signal.signal(signal.SIGINT, old_sigint)

    finally:
        cleanup()
        sys.exit(0)

if __name__ == "__main__":
    main()
