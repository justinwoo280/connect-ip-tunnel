import subprocess
import sys
import os

# 打印调试信息，帮助定位项目路径
print(f"[git] cwd = {os.getcwd()}")
print(f"[git] Scanning filesystem for git repo with go.mod ...")

def find_project_root():
    # 扫描几个常见位置
    search_roots = ["/home/user", "/root", "/tmp", "/workspace", "/app", os.getcwd()]
    for base in search_roots:
        if not os.path.isdir(base):
            continue
        for entry in os.scandir(base):
            if entry.is_dir():
                gomod = os.path.join(entry.path, "go.mod")
                gitdir = os.path.join(entry.path, ".git")
                if os.path.exists(gomod) and os.path.isdir(gitdir):
                    return entry.path
        # 检查 base 本身
        if os.path.exists(os.path.join(base, "go.mod")) and os.path.isdir(os.path.join(base, ".git")):
            return base
    raise RuntimeError(f"Cannot find project root. cwd={os.getcwd()}")

cwd = find_project_root()
print(f"[git] Project root: {cwd}")

def run(cmd, check=True):
    print(f"[git] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if check and result.returncode != 0:
        print(f"[git] ERROR: command failed with code {result.returncode}")
        sys.exit(1)
    return result

# 配置 git 用户信息
run(["git", "config", "user.email", "v0-bot@vercel.com"])
run(["git", "config", "user.name", "v0"])

# 设置远程仓库
run(["git", "remote", "set-url", "origin", "https://github.com/justinwoo280/connect-ip-tunnel.git"], check=False)

# 查看当前状态
run(["git", "status"])

# 删除 scripts 目录下的 git 脚本（不应提交到仓库）
for f in ["git-push.sh", "git-push.mjs", "git-push.py"]:
    path = os.path.join(cwd, "scripts", f)
    if os.path.exists(path):
        os.remove(path)
        print(f"[git] Removed temp script: {f}")

# 暂存所有变更
run(["git", "add", "-A"])

# 提交
run(["git", "commit", "-m", "refactor(security): replace HTTP auth with mTLS\n\n- Remove security/auth package (Bearer/Basic/Custom Header)\n- Add mTLS support: ClientCertFile/ClientKeyFile on client side\n- Add mTLS support: EnableMTLS/ClientCAFile/ClientCAs on server side\n- Wire mTLS config through buildTLSOptions() in client engine\n- Add loadClientCAPool() helper to tls/server.go\n- Remove AuthConfig from option/config.go\n- Remove authProv and HTTP auth check from server/handler.go\n- Update README, ARCHITECTURE, TECH_STACK docs"])

# 推送到远程
run(["git", "push", "origin", "main"])

print("[git] Successfully pushed to origin/main")
