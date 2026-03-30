import { execSync } from 'child_process';

const REMOTE_URL = 'https://github.com/justinwoo280/connect-ip-tunnel.git';
const CWD = '/vercel/share/v0-project';

function run(cmd, opts = {}) {
  console.log(`[git] $ ${cmd}`);
  try {
    const output = execSync(cmd, { cwd: CWD, encoding: 'utf8', ...opts });
    if (output) process.stdout.write(output);
    return output;
  } catch (err) {
    if (opts.ignoreError) {
      console.log(`[git] 忽略错误: ${err.message}`);
      return '';
    }
    throw err;
  }
}

// 1. 配置 git 用户
run('git config user.email "v0@vercel.com"');
run('git config user.name "v0"');

// 2. 查看当前状态
run('git status');

// 3. 设置远程仓库
try {
  run(`git remote set-url origin ${REMOTE_URL}`);
  console.log('[git] 已更新 remote origin');
} catch {
  run(`git remote add origin ${REMOTE_URL}`);
  console.log('[git] 已添加 remote origin');
}

// 4. 暂存所有变更
run('git add -A');

// 5. 提交
const commitMsg = `refactor(auth): 以 mTLS 替代 HTTP 鉴权方案

- 废除 security/auth 包及全部 HTTP 鉴权代码（Bearer/Basic/Custom Header）
- 补全 ClientOptions.ClientCertFile / ClientKeyFile 字段
- 新增 ServerOptions.EnableMTLS / ClientCAs / ClientCAFile 字段
- server.go 支持条件启用 mTLS，支持自定义 CA 文件或回退系统 CA
- engine/client_engine.go buildTLSOptions() 传递 mTLS 证书配置
- option/config.go 移除 AuthConfig，TLSConfig 新增 mTLS 字段
- server/handler.go 移除 authenticate() 函数和 HTTP 鉴权检查
- 更新 README.md / ARCHITECTURE.md / TECH_STACK.md 反映新方案`;

try {
  run(`git commit -m ${JSON.stringify(commitMsg)}`);
} catch (err) {
  if (err.message.includes('nothing to commit')) {
    console.log('[git] 无变更可提交，跳过 commit');
  } else {
    throw err;
  }
}

// 6. 推送
run('git push origin HEAD');

console.log('\n[git] 推送完成！');
