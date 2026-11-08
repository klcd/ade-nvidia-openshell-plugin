#!/usr/bin/env python3
"""
OpenShell Dynamic Sandbox Bridge for OpenAI Codex in Orca & Terminal

Features:
- Dynamically discovers project workspace root for any project.
- Merges global policies (~/.agents/policies/) and project policies (<project>/.agents/policies/).
- Applies policy directly during sandbox creation (--policy) in <1 second (avoiding slow policy-set delays).
- Probes and discovery bypass to host Codex to prevent catalog timeouts.
- Staging ~/.codex credentials (preserving ChatGPT Team subscription OAuth).
- Preserves git repository metadata and stages workspace.
- Full PTY terminal echo filtering for JSON-RPC 2.0 app-server protocol.
- Sleep management: pauses container via docker pause on prolonged inactivity (CODEX_IDLE_TIMEOUT).
- Automatic wakeup: resumes in <50ms on new user activity.
- Automatic teardown: downloads workspace modifications back to host and deletes the container on tab close.
"""

import sys
import os
import subprocess
import threading
import json
import time
import re
import signal
import pty
import select
import shutil
import glob

def find_host_binary(name="codex"):
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

REAL_CODEX = find_host_binary("codex")
DEBUG_LOG = os.path.expanduser("~/.gemini/openshell-bridge.log")
IDLE_TIMEOUT = int(os.environ.get("CODEX_IDLE_TIMEOUT", "600"))

def log_debug(msg):
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG), exist_ok=True)
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [PID {os.getpid()}] {msg}\n")
    except Exception:
        pass

def rewrite_jsonrpc_paths(line_bytes, src_prefix, dst_prefix):
    try:
        obj = json.loads(line_bytes)
        modified = False
        def walk(o):
            nonlocal modified
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(v, str) and src_prefix in v:
                        o[k] = v.replace(src_prefix, dst_prefix)
                        modified = True
                    else:
                        walk(v)
            elif isinstance(o, list):
                for item in o:
                    walk(item)
        walk(obj)
        if modified:
            return json.dumps(obj).encode("utf-8")
    except Exception:
        pass
    return line_bytes

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

def get_runtime_container_id(sandbox_name):
    try:
        res = subprocess.run(
            ["docker", "ps", "--filter", f"name=openshell-{sandbox_name}-runtime", "--format", "{{.ID}}"],
            stdout=subprocess.PIPE,
            text=True
        )
        return res.stdout.strip()
    except Exception:
        return None

def main():
    args = sys.argv[1:]
    cwd = os.getcwd()

    # Fast paths: help or version
    for arg in args:
        if arg in ("--version", "-V", "--help", "-h"):
            if REAL_CODEX:
                os.execv(REAL_CODEX, [REAL_CODEX] + args)

    # Fast path: Orca model discovery / probe queries
    is_probe = False
    if "probe" in cwd or "tmp" in cwd or "probe" in "".join(args):
        is_probe = True

    if is_probe and REAL_CODEX:
        os.execv(REAL_CODEX, [REAL_CODEX] + args)

    proj_root = detect_project_root()
    proj_name = os.path.basename(proj_root)
    safe_proj = re.sub(r'[^a-zA-Z0-9_-]', '-', proj_name).lower()
    pid = os.getpid()

    # OpenShell sandbox names must be <= 19 characters
    sandbox_name = f"cx-{safe_proj[:8].strip('-')}-{pid % 100000}"
    log_debug(f"Starting session for {proj_name} (sandbox {sandbox_name}), args={args}")

    # Discover & merge policies
    global_policies = os.path.expanduser("~/.agents/policies")
    proj_policies = os.path.join(proj_root, ".agents", "policies")
    merged_policy = merge_policies([global_policies, proj_policies])

    p_tmp = f"/tmp/policy-{pid}.json"
    create_cmd = [
        "openshell", "sandbox", "create",
        "--name", sandbox_name,
        "--from", "openshell-codex:latest",
        "--provider", "codex",
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
        if REAL_CODEX:
            log_debug("Falling back to host codex.")
            os.execv(REAL_CODEX, [REAL_CODEX] + args)
        else:
            sys.exit(1)

    if os.path.exists(p_tmp):
        try: os.remove(p_tmp)
        except Exception: pass

    is_paused = False
    pause_lock = threading.Lock()
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
                # Sync back refreshed tokens to host
                subprocess.run(
                    ["openshell", "sandbox", "download", sandbox_name, "/sandbox/.codex/auth.json", os.path.expanduser("~/.codex/auth.json")],
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
        # Stage ~/.codex credentials & workspace trust
        stage_dir = f"/tmp/codex-stage-{pid}"
        os.makedirs(f"{stage_dir}/.codex", exist_ok=True)
        for fname in ["auth.json", "version.json"]:
            src = os.path.expanduser(f"~/.codex/{fname}")
            if os.path.exists(src):
                shutil.copy(src, f"{stage_dir}/.codex/{fname}")

        with open(f"{stage_dir}/.codex/config.toml", "w") as f:
            f.write(f'''
[projects."/sandbox"]
trust_level = "trusted"

[projects."/sandbox/{proj_name}"]
trust_level = "trusted"
''')
        with open(f"{stage_dir}/.gitconfig", "w") as f:
            f.write("[safe]\n\tdirectory = *\n")

        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.codex", "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openshell", "sandbox", "upload", sandbox_name, f"{stage_dir}/.gitconfig", "/sandbox/.gitconfig"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(stage_dir, ignore_errors=True)
        
        # Upload project workspace
        subprocess.run(["openshell", "sandbox", "upload", "--no-git-ignore", sandbox_name, proj_root, "/sandbox"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Resolve runtime container id for sleep management
        runtime_cid = get_runtime_container_id(sandbox_name)
        
        # Setup command inside sandbox
        effective_args = list(args)
        if "app-server" not in effective_args and "--no-daemon" not in effective_args and "exec" not in effective_args:
            effective_args.append("--no-daemon")

        cmd = [
            "openshell", "sandbox", "exec",
            "--name", sandbox_name,
            "--workdir", f"/sandbox/{proj_name}",
            "--tty",
            "--",
            "codex"
        ] + effective_args

        if "app-server" not in args:
            # Interactive CLI mode: inherit stdio directly so openshell handles raw TTY,
            # terminal window dimensions (SIGWINCH), and mouse escape codes cleanly without echoing garbage.
            old_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                proc = subprocess.Popen(cmd)
                proc.wait()
            finally:
                signal.signal(signal.SIGINT, old_sigint)
            return

        # Orca app-server mode: Start PTY session for JSON-RPC 2.0 filtering and path rewriting
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            cmd,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True
        )
        os.close(slave)
        
        last_activity_time = time.time()
        sent_client_ids = set()
        sent_exact_lines = set()
        
        def forward_stdin():
            nonlocal last_activity_time, is_paused
            buf = b""
            try:
                while True:
                    chunk = os.read(0, 4096)
                    if not chunk:
                        break
                    
                    with pause_lock:
                        if is_paused and runtime_cid:
                            subprocess.run(["docker", "unpause", runtime_cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            is_paused = False
                            log_debug(f"Woke up sandbox {sandbox_name} from sleep.")
                        last_activity_time = time.time()
                        
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        stripped = line.strip()
                        if stripped:
                            # Path rewrite host -> container
                            rewritten_line = rewrite_jsonrpc_paths(line, proj_root, f"/sandbox/{proj_name}")
                            if rewritten_line != line:
                                chunk = chunk.replace(line, rewritten_line)
                                line = rewritten_line
                                stripped = line.strip()
                            sent_exact_lines.add(stripped)
                            try:
                                obj = json.loads(stripped)
                                if "id" in obj and "method" in obj:
                                    sent_client_ids.add(obj["id"])
                            except Exception:
                                pass
                    os.write(master, chunk)
            except Exception:
                pass

        t = threading.Thread(target=forward_stdin, daemon=True)
        t.start()
        
        out_buf = b""
        while True:
            r, _, _ = select.select([master], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                    
                with pause_lock:
                    last_activity_time = time.time()
                    
                out_buf += chunk
                if "app-server" in args:
                    while b"\n" in out_buf:
                        line, out_buf = out_buf.split(b"\n", 1)
                        clean_line = line.strip().replace(b"\r", b"")
                        if not clean_line:
                            continue
                        
                        is_echo = False
                        if clean_line in sent_exact_lines:
                            is_echo = True
                        else:
                            try:
                                obj = json.loads(clean_line)
                                if "id" in obj and "method" in obj and obj["id"] in sent_client_ids:
                                    is_echo = True
                                elif obj.get("method") == "warning" and "diagnostic logs" in obj.get("params", {}).get("message", ""):
                                    is_echo = True
                            except Exception:
                                pass
                        
                        if not is_echo:
                            os.write(1, clean_line + b"\n")
                else:
                    os.write(1, out_buf)
                    out_buf = b""
            else:
                now = time.time()
                if not is_paused and runtime_cid and (now - last_activity_time > IDLE_TIMEOUT):
                    with pause_lock:
                        if not is_paused:
                            subprocess.run(["docker", "pause", runtime_cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            is_paused = True
                            log_debug(f"Sandbox {sandbox_name} went to sleep after {IDLE_TIMEOUT}s idle.")
                            
            if proc.poll() is not None:
                while True:
                    r, _, _ = select.select([master], [], [], 0.05)
                    if not r:
                        break
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out_buf += chunk
                    if "app-server" in args:
                        while b"\n" in out_buf:
                            line, out_buf = out_buf.split(b"\n", 1)
                            clean_line = line.strip().replace(b"\r", b"")
                            if clean_line and clean_line not in sent_exact_lines:
                                try:
                                    obj = json.loads(clean_line)
                                    if obj.get("method") == "warning" and "diagnostic logs" in obj.get("params", {}).get("message", ""):
                                        continue
                                except Exception:
                                    pass
                                os.write(1, clean_line + b"\n")
                    else:
                        os.write(1, out_buf)
                        out_buf = b""
                break
    finally:
        cleanup()
        sys.exit(0)

if __name__ == "__main__":
    main()
