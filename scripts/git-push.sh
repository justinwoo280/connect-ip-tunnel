#!/bin/bash
set -e

REMOTE_URL="https://github.com/justinwoo280/connect-ip-tunnel.git"

cd /vercel/share/v0-project

echo "[git] 当前状态："
git status

echo ""
echo "[git] 配置 git 用户信息..."
git config user.email "v0@vercel.com"
git config user.name "v0"

echo ""
echo "[git] 检查远程仓库..."
if git remote get-url origin 2>/dev/null; then
  git remote set-url origin "$REMOTE_URL"
  echo "[git] 已更新 remote origin -> $REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
  echo "[git] 已添加 remote origin -> $REMOTE_URL"
fi

echo ""
echo "[git] 暂存所有变更..."
git add -A

echo ""
echo "[git] 提交变更..."
git commit -m "refactor(auth): 以 mTLS 替代 HTTP 鉴权方案

- 废除 security/auth 包及全部 HTTP 鉴权代码（Bearer/Basic/Custom Header）
- 补全 ClientOptions.ClientCertFile / ClientCertKeyFile 字段
- 新增 ServerOptions.EnableMTLS / ClientCAs / ClientCAFile 字段
- server.go 支持条件启用 mTLS，支持自定义 CA 文件或回退系统 CA
- engine/client_engine.go buildTLSOptions() 传递 mTLS 证书配置
- option/config.go 移除 AuthConfig，TLSConfig 新增 mTLS 字段
- server/handler.go 移除 authenticate() 函数和 HTTP 鉴权检查
- 更新 README.md / ARCHITECTURE.md / TECH_STACK.md 反映新方案" || echo "[git] 无变更可提交"

echo ""
echo "[git] 推送到远程仓库..."
git push origin HEAD

echo ""
echo "[git] 完成！"
