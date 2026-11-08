#!/usr/bin/env python3
"""
OpenShell Dynamic Sandbox Bridge for Antigravity CLI (agy)

Features:
- Dynamically discovers project workspace root.
- Merges global policies (~/.agents/policies/) and project policies (<project>/.agents/policies/).
- Applies Landlock policy directly during sandbox creation (--policy) in <1 second.
- Fast paths for version/help to host agy.
- Stages ~/.gemini credentials, cache (including onboarding state), and ~/.gitconfig inside container.
- Pre-configures color scheme and disables data collection telemetry so onboarding prompts never show.
- Handles both non-interactive (--print / prompt) and interactive TUI sessions cleanly.
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

DEBUG_LOG = os.path.expanduser("~/.gemini/openshell-bridge.log")

def find_host_binary(name="agy"):
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

REAL_AGY = find_host_binary("agy")

def log_debug(msg):
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [PID {os.getpid()}] {msg}\n")
    except Exception:
        pass

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

    # Fast paths: help or version (or if host agy exists and requested)
    for arg in args:
        if arg in ("--version", "-V", "--help", "-h"):
            if REAL_AGY:
                os.execv(REAL_AGY, [REAL_AGY] + args)

    proj_root = detect_project_root()
    proj_name = os.path.basename(proj_root)
    safe_proj = re.sub(r'[^a-zA-Z0-9_-]', '-', proj_name).lower()
    pid = os.getpid()

    # OpenShell sandbox names must be <= 19 characters
    sandbox_name = f"ag-{safe_proj[:8].strip('-')}-{pid % 100000}"
    log_debug(f"Starting session for {proj_name} (sandbox {sandbox_name}), args={args}")

    # Discover & merge policies
    global_policies = os.path.expanduser("~/.agents/policies")
    proj_policies = os.path.join(proj_root, ".agents", "policies")
    merged_policy = merge_policies([global_policies, proj_policies])

    p_tmp = f"/tmp/policy-agy-{pid}.json"
    create_cmd = [
        "openshell", "sandbox", "create",
        "--name", sandbox_name,
        "--from", "openshell-antigravity:latest",
        "--provider", "antigravity",
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
        if REAL_AGY:
            log_debug("Falling back to host agy.")
            os.execv(REAL_AGY, [REAL_AGY] + args)
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
                # Sync back refreshed tokens or updated settings to host
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, "/sandbox/.gemini/antigravity-cli/antigravity-oauth-token", os.path.expanduser("~/.gemini/antigravity-cli/antigravity-oauth-token")],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, "/sandbox/.gemini/antigravity-cli/settings.json", os.path.expanduser("~/.gemini/antigravity-cli/settings.json")],
                    check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, "/sandbox/.gemini/antigravity-cli/cache/onboarding.json", os.path.expanduser("~/.gemini/antigravity-cli/cache/onboarding.json")],
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
        # Stage ~/.gemini and ~/.gitconfig
        stage_dir = f"/tmp/agy-stage-{pid}"
        os.makedirs(f"{stage_dir}/.gemini/antigravity-cli/cache", exist_ok=True)
        
        # 1. Base ~/.gemini config and credentials
        for fname in ["oauth_creds.json", "settings.json", "google_accounts.json", "installation_id", "projects.json"]:
            src = os.path.expanduser(f"~/.gemini/{fname}")
            if os.path.exists(src):
                shutil.copy(src, f"{stage_dir}/.gemini/{fname}")

        # Stage ~/.gemini/config if present (projects, hooks, etc.)
        config_src = os.path.expanduser("~/.gemini/config")
        if os.path.isdir(config_src):
            shutil.copytree(config_src, f"{stage_dir}/.gemini/config", dirs_exist_ok=True)

        # 2. ~/.gemini/antigravity-cli state & credentials
        for fname in ["antigravity-oauth-token", "installation_id", "jetbox_summaries_proto.pb"]:
            src = os.path.expanduser(f"~/.gemini/antigravity-cli/{fname}")
            if os.path.exists(src):
                shutil.copy(src, f"{stage_dir}/.gemini/antigravity-cli/{fname}")

        # Stage jetski_state.pbtxt with complete onboarding flag
        jetski_src = os.path.expanduser("~/.gemini/antigravity-cli/jetski_state.pbtxt")
        jetski_content = ""
        if os.path.exists(jetski_src):
            try:
                with open(jetski_src) as f:
                    jetski_content = f.read()
            except Exception:
                pass
        if "agent_onboarding_completed" not in jetski_content:
            jetski_content += "\nagent_onboarding_completed: AGENT_ONBOARDING_STATE_COMPLETED\n"
        if "POST_ONBOARDING_STEP_TYPE_MANAGER_WELCOME" not in jetski_content:
            jetski_content += """
post_onboarding: {
  completed_steps: POST_ONBOARDING_STEP_TYPE_MANAGER_WELCOME
  completed_steps: POST_ONBOARDING_STEP_TYPE_USAGE_MODE
  completed_steps: POST_ONBOARDING_STEP_TYPE_AGENT_CONFIGURATION
  completed_steps: POST_ONBOARDING_STEP_TYPE_ADD_WORKSPACE
}
"""
        with open(f"{stage_dir}/.gemini/antigravity-cli/jetski_state.pbtxt", "w") as f:
            f.write(jetski_content.strip() + "\n")

        # 3. Stage cache/onboarding.json (bypasses theme and terms/data collection prompts)
        onboarding_file = f"{stage_dir}/.gemini/antigravity-cli/cache/onboarding.json"
        host_onboarding = os.path.expanduser("~/.gemini/antigravity-cli/cache/onboarding.json")
        onboarding_data = {
            "consumerOnboardingComplete": True,
            "enterpriseOnboardingComplete": False,
            "onboardingComplete": True
        }
        if os.path.exists(host_onboarding):
            try:
                with open(host_onboarding) as f:
                    data = json.load(f)
                    onboarding_data.update(data)
            except Exception:
                pass
        onboarding_data["consumerOnboardingComplete"] = True
        onboarding_data["onboardingComplete"] = True
        with open(onboarding_file, "w") as f:
            json.dump(onboarding_data, f, indent=2)

        # 4. Pre-configure ~/.gemini/antigravity-cli/settings.json
        cli_settings_src = os.path.expanduser("~/.gemini/antigravity-cli/settings.json")
        cli_settings = {}
        if os.path.exists(cli_settings_src):
            try:
                with open(cli_settings_src) as f:
                    cli_settings = json.load(f)
            except Exception:
                pass

        if "colorScheme" not in cli_settings:
            cli_settings["colorScheme"] = "tokyo night"
        if "telemetryEnabled" not in cli_settings:
            cli_settings["telemetryEnabled"] = False
        tw = cli_settings.setdefault("trustedWorkspaces", [])
        for p in ["/sandbox", f"/sandbox/{proj_name}", proj_root]:
            if p not in tw:
                tw.append(p)

        with open(f"{stage_dir}/.gemini/antigravity-cli/settings.json", "w") as f:
            json.dump(cli_settings, f, indent=2)

        with open(f"{stage_dir}/.gitconfig", "w") as f:
            f.write("[safe]\n\tdirectory = *\n")

        # Stage ~/.gemini and ~/.gitconfig in /sandbox (which /home/ubuntu/.gemini symlinks to)
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.gemini", "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.gitconfig", "/sandbox/.gitconfig"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(stage_dir, ignore_errors=True)

        # Upload project workspace
        subprocess.run(["openshell", "sandbox", "upload", "--no-git-ignore", sandbox_name, proj_root, "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cmd = [
            "openshell", "sandbox", "exec",
            "--name", sandbox_name,
            "--workdir", f"/sandbox/{proj_name}",
            "--tty",
            "--",
            "agy"
        ] + args

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
