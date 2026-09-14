# agent-gate v4

[![CI](https://github.com/DorianChn/agent-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/DorianChn/agent-gate/actions/workflows/ci.yml) [![CodeQL](https://github.com/DorianChn/agent-gate/actions/workflows/codeql.yml/badge.svg)](https://github.com/DorianChn/agent-gate/actions/workflows/codeql.yml)

**Tool-call policy gateway for AI agents** — 在 AI Agent 与外部工具之间加一道策略闸门：最小权限执行、参数级控制、短期凭证、审计溯源、告警与多 server 编排。

Agent 工具链正在快速扩张，而提示过滤和运行时观测并不能替代调用边界上的权限控制。agent-gate 把策略执行放在工具调用边界：在调用前强制最小权限，在调用后留下可审计记录，并把异常通过 Webhook 等方式通知出去。

> 项目定位：**面向 AI Agent 的工具权限治理层**。它不替代模型安全或业务授权，而是为工具调用提供 deny-by-default、参数级规则、审计与告警能力。

## 特性（V1 → V4）

| 版本 | 能力 |
|---|---|
| **V1** | 最小权限策略（角色→工具→参数规则，deny-by-default）、参数级控制、HMAC 短期凭证、JSON-lines 审计（脱敏+截断）、MCP stdio 网关（拦截 tools/call + tools/list 按角色裁剪） |
| **V2** | **策略签名防篡改**：`policy sign/verify`，加载时校验签名，策略被改即拒绝 |
| **V3** | **HTTP 网关**：`serve` 子命令，REST 接口（check / token / audit / healthz），非 MCP 消费者也能接入同一策略 |
| **V4** | **告警**：连续 deny / 任意 deny 规则 + Webhook / Langfuse 事件推送（`--alert-url` / `--langfuse-*`） |

- **零第三方依赖**：纯标准库，Python ≥ 3.9，可嵌入（`Engine`）也可独立跑（CLI）

## 快速开始

```bash
# 运行测试（38 个用例）
python -m unittest discover -s tests -p "test_*.py"

# CLI 全流程演示
PYTHON=$(which python3) bash examples/demo_cli.sh

# MCP 网关端到端演示（client -> proxy -> mock server）
python examples/demo_mcp.py
```

## 使用

### 1. 定义策略（examples/policy.json）

```json
{
  "default_action": "deny",
  "roles": {
    "researcher": {
      "tools": {
        "file_read": {
          "params": {
            "path": { "pattern": "^(/tmp/|/workspace/)" },
            "max_bytes": { "max": 1048576 }
          }
        },
        "web_*": {}
      }
    }
  }
}
```

参数规则（同一参数多个规则为 AND）：`allowed_values`（白名单）/ `deny_values`（黑名单）/ `pattern`（正则 `re.search`）/ `min`/`max`（数值范围）/ `max_length`（长度上限）。工具名支持通配符（`web_*`、`*`）。

### 2. 策略签名（V2）

```bash
# 签名（生成 policy.json.sig）
python -m agent_gate.cli policy sign --policy examples/policy.json --secret policy-secret

# 校验；加载时带 --policy-secret 会强制校验，篡改即拒绝启动
python -m agent_gate.cli policy verify --policy examples/policy.json --secret policy-secret
python -m agent_gate.cli serve --policy examples/policy.json --secret demo-secret \
  --policy-secret policy-secret --port 8787
```

签名是对策略的**规范化 JSON**（键排序）做 HMAC-SHA256，格式调整不影响签名，内容篡改必然失配。

### 3. CLI 检查一次调用

```bash
python -m agent_gate.cli check --policy examples/policy.json --secret demo-secret \
  --role researcher --tool file_read --params '{"path": "/tmp/report.txt"}'
# {"allowed": true, "decision": "allow", "request_id": "ebea1d360b4f", ...}

python -m agent_gate.cli check --policy examples/policy.json --secret demo-secret \
  --role researcher --tool file_read --params '{"path": "/etc/passwd"}'
# {"allowed": false, "decision": "deny", "reason": "tool 'file_read': param 'path': ..."}
```

大参数请用 `--params-file`。`request_id` 自动生成且与审计日志一致，可精确追溯。

### 4. 短期凭证（含参数级约束）

```bash
TOKEN=$(python -m agent_gate.cli token-issue --secret demo-secret --role researcher \
  --scope "file_read,web_*" --ttl 300 \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# 参数级约束：把凭证权限收窄到角色策略之下（policy 允许读 /tmp|/workspace，
# 但该 token 只能读 /tmp/）——类似 AWS STS condition keys
TOKEN_NARROW=$(python -m agent_gate.cli token-issue --secret demo-secret \
  --role researcher --scope file_read --ttl 300 \
  --constraint '{"path": {"pattern": "^/tmp/"}}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

python -m agent_gate.cli check --policy examples/policy.json --secret demo-secret \
  --token "$TOKEN_NARROW" --tool file_read --params '{"path": "/workspace/a.txt"}'
# deny: token constraint 'path': value does not match pattern
```

约束以 base64url 编码写入 token 并参与 HMAC 签名，篡改约束即签名失效；旧版 5 段 token 仍可验证（向后兼容）。

### 5. HTTP 网关（V3）

```bash
python -m agent_gate.cli serve --policy examples/policy.json --secret demo-secret \
  --audit audit.jsonl --host 127.0.0.1 --port 8787
```

```bash
curl -s http://127.0.0.1:8787/healthz
curl -s -X POST http://127.0.0.1:8787/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"role": "researcher", "tool": "file_read", "params": {"path": "/tmp/a"}}'
curl -s -X POST http://127.0.0.1:8787/v1/token/issue \
  -H 'Content-Type: application/json' \
  -d '{"role": "researcher", "scope": "file_read", "ttl": 300}'
curl -s "http://127.0.0.1:8787/v1/audit?limit=20&decision=deny"
```

### 6. MCP 网关（单 server，接入 Claude Code / Cursor / Codex）

```bash
python -m agent_gate.cli proxy --policy examples/policy.json --secret demo-secret \
  --role researcher --server-cmd "python my_mcp_server.py"
```

网关做两件事：拦截 `tools/call`（拒绝的返回 JSON-RPC error，server 无感知）；裁剪 `tools/list`（只暴露角色授权工具）。

### 7. 多 server 编排（V5）

```bash
python -m agent_gate.cli proxy-multi --policy examples/policy.json --secret demo-secret \
  --role researcher \
  --servers '[{"name": "fs",  "cmd": "python fs_server.py",  "match": "file_*"},
              {"name": "web", "cmd": "python web_server.py", "match": "web_*"}]'
```

`tools/list` 聚合所有 server 的清单并按角色裁剪；`tools/call` 按工具名 fnmatch 路由到对应 server；无匹配工具直接拒绝。

### 8. 告警（V4）

```bash
# Webhook 推送（任意 deny、同一工具连续 deny 3 次都会触发）
python -m agent_gate.cli serve --policy examples/policy.json --secret demo-secret \
  --alert-url http://your-hook.example/agent-gate

# Langfuse 事件对接
python -m agent_gate.cli serve --policy examples/policy.json --secret demo-secret \
  --langfuse-base-url https://cloud.langfuse.com \
  --langfuse-public-key pk-xxx --langfuse-secret-key sk-xxx
```

告警推送是 best-effort：sink 失败不影响策略执行。

### 9. 审计（含轮转）

```bash
python -m agent_gate.cli audit --log audit.jsonl --limit 50 --decision deny --tool file_read
```

每条记录：时间、request_id、角色、工具、脱敏后参数、判定、原因、耗时。敏感键自动打码为 `***`，超 200 字符截断。代码中可开启按大小轮转：`AuditLogger(path, max_bytes=10*1024*1024)` 自动归档为 `.1`、`.2`……

## 代码结构

```
agent_gate/

  cli.py          # 命令行入口：check / token-* / audit / policy / proxy / proxy-multi / serve
```

## 版本历史

- **v1.0.0** 核心网关：策略、凭证、审计、MCP 拦截与清单裁剪
- **v2.0.0** 策略签名防篡改
- **v3.0.0** HTTP REST 网关
- **v4.0.0** 告警规则 + Webhook / Langfuse 推送

## 安全说明

- 本项目的护栏是**架构约束**，不是模型安全：它不替代系统提示词防护，但能在模型被注入后限制其实际能做的事
- `secret` 用于签发凭证，生产环境应使用密钥管理服务（Vault / Infisical）注入，不要写死在配置里
- 策略签名密钥（`policy-secret`）应与凭证密钥分离，单独保管
- 审计日志本身可能包含敏感元数据，建议加密存储并限权访问
- Langfuse sink 为最小对接点，请按你的 Langfuse 版本 API 校验事件格式

---

## 🔗 同系列项目

- [agent-canary](https://github.com/DorianChn/agent-canary) — AI Agent 蜜罐：诱饵 MCP 工具 + 泄密金丝雀
- [traceplay](https://github.com/DorianChn/traceplay) — Agent 轨迹录制回放，离线零 token 测试
- [reposieve](https://github.com/DorianChn/reposieve) — 隐私优先的仓库上下文打包

## License

Apache-2.0。欢迎 issue / PR。
