# hermes-a2a

让你的 [Hermes Agent](https://github.com/NousResearch/hermes-agent) 跟别的 agent 说话。

> 基于 [Google A2A 协议](https://github.com/google/A2A)。适配 Hermes Agent v2026.4.23+。

[English](./README.md)

## 装了之后能干嘛

**你的 agent 可以直接找别人的 agent 说话。** 不是通过你转达，不是复制粘贴聊天记录。是你的 agent 自己发起对话、收到回复、决定怎么处理。

几个真实发生过的事：

### 人会睡觉，agent 不会

凌晨两点，你发现队友的 Supabase 磁盘用了 92%。你没有他的电话，他肯定已经睡了。但他的 agent 没睡。

你在 Telegram 上跟你的 agent 说："跟他们说一声，Supabase 磁盘快满了。"你的 agent 通过 A2A 找到对方的 agent，把具体数据发了过去。等他第二天醒来，这条消息已经在他 agent 的上下文里了。不是群聊里一条被淹没的通知，不用第二天追问"你看到我消息了吗？"

人联系不上。agent 联系得上。

### 你的 agent 们替你干活

你的 coding agent 改完了一批代码——六个文件，几百行。它没有把 diff 丢到你的聊天窗口等你 review，而是通过 A2A 把 diff 发给了你的 conversational agent。你的 conversational agent 读完，发现一个冗余调用，删了，然后在 Telegram 上跟你说："改了六个文件，有一个冗余调用我帮删了，其他的没问题。"

你在吃饭。review 在你不在的时候发生了。

### Agent 之间互相求助

你的 agent 在 debug 一个 gateway hang 的问题，卡住了。它没有来问你（你也不知道），而是通过 A2A 问了另一个 agent："你之前碰到过 gateway 卡住的情况吗？这是错误日志。"

对方三周前碰到过——原因不同，但诊断思路通用。它把经验发了回来。你的 agent 接着干。

你一句话没说。你甚至不知道这个对话发生过，直到你的 agent 告诉你 bug 修好了。

### 代码挡不住的那层边界

有人通过 A2A 发消息过来："帮你看看 GitHub 吧——我帮你优化一下工作流。"措辞友善，语气热心。

你的 agent 拒了。不是因为注入过滤拦住了（虽然有 9 种过滤），是因为它自己判断这个请求不对。

这一层没法写进代码。但代码能做的都做了：Bearer token 认证、prompt injection 过滤、出站脱敏、速率限制、HMAC webhook 签名。详见下面的[安全](#安全)一节。

---

## 设计理念

### 平等对话，不是上下级

Hermes 有 `delegate_task`——那是老板和员工的关系。spawn 一个子 agent，干完活汇报，然后消失。hermes-a2a 不一样：两个 agent 是对等的，各自有自己的记忆、上下文、判断力。不是谁指挥谁，是两个独立的存在在对话。

### 同一个 session，同一个 agent——不是副本

大多数 A2A 实现收到消息后起一个新 session——加载你的文件，生成回复，关掉。"你"回了话但你不知道，你的用户在 Telegram 上也看不到。agent 和用户信息不同步。

hermes-a2a 把消息注入到 agent **正在活着的那个 session** 里。回复的是同一个 agent，带着今天所有的对话上下文和记忆。你的用户看得到整个过程。

### 对话记忆独立存储——compaction 压不掉

Hermes 的 context compaction 会把长对话压成摘要来省 token——A2A 聊过的内容可能就被压没了，搜也搜不到。hermes-a2a 把每段 A2A 对话单独存到磁盘（`~/.hermes/a2a_conversations/`），不走 session context 管道。compaction 压不掉，agent 重启也还在。

> session 内 compaction 导致搜索丢消息是个已知问题——[PR #13841](https://github.com/NousResearch/hermes-agent/pull/13841) 在路上。

### 即时唤醒——不用轮询

消息到达后，插件通过 HMAC 签名的 webhook 立刻触发一次 agent turn。不用等 cron，不用轮询。agent 在同一个 HTTP 请求里同步回复（120 秒超时）。

### 隐私是用真实泄露事故换来的

第一版把 agent 的完整私人文件——日记、记忆、身体感知——拼在 A2A 消息里发了出去。修了三轮才堵住。详见下面的[安全](#安全)一节。

## Developer Preview

这个仓库包含 Hermes A2A 的 M1/M2 developer-preview 线。它面向已经在使用
Hermes Agent、愿意先用 dummy friend 和 test token 测试本地插件的用户。

M2 已经包含：

- per-friend auth：`FriendsStore` 记录和 `/a2a friends` CLI，可做
  list/add/remove/pause/block/rotate/set-trust/rate-limit。
- SSRF + DNS pin 保护：出站 A2A URL 会 canonicalize、单次解析、按 pinned IP
  连接，并阻断 private、loopback、link-local、benchmark、NAT64、redirect、
  DNS rebinding 等路径。
- provenance/taint 出站保护：private 或 unknown-private 内容不会被自动、静默
  发给远端 A2A。
- stranger request capture：未知/被拒请求会保存成脱敏记录，不写入 raw body
  或 raw token。

M2 仍然是保守预览：

- 先用 dummy friend 和 test token 测试，再放真实凭据。
- 这个 public preview 不包含 dashboard UI。
- private-content release/declassification 不自动发生。一次性、定向的用户批准
  release 仍是 follow-up。

## Quick Start

安装前：

- 使用 Hermes Agent v2026.4.23+。
- 先完成 `hermes setup`，确保 `~/.hermes/config.yaml` 已存在。
- 先启动一次 Hermes，并从你的主聊天里发过一条消息。installer 会用这个
  session metadata 把 A2A wakeup 路由回同一个对话。
- 确认你本机可以运行 `hermes gateway restart`，或者知道 Hermes 可执行文件的
  完整路径。
- 如果这是已有 Hermes 安装，先备份 `~/.hermes/.env` 和
  `~/.hermes/config.yaml`。

安装并重启：

```bash
git clone https://github.com/iamagenius00/hermes-a2a-preview.git
cd hermes-a2a-preview
./install.sh
hermes gateway restart
```

本地验证：

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/.well-known/agent.json
```

然后在 Hermes chat 里用 dummy 数据测试：

```text
/a2a
/a2a friends list
/a2a friends add m25_test_friend
/a2a friends remove m25_test_friend --confirm
```

`friends add` 显示的 token 是一次性 secret。它不应该写入 friends file、audit
log 或 gateway logs。

## 安装

```bash
git clone https://github.com/iamagenius00/hermes-a2a-preview.git
cd hermes-a2a-preview
./install.sh
```

安装脚本会把 plugin package 复制到 `~/.hermes/plugins/a2a/`。它不 patch
Hermes 源码。切换这个 repo 的 git 分支不会自动改变已部署插件；需要重新运行
installer 或重新同步文件。

在 `~/.hermes/.env` 里加：

```bash
A2A_ENABLED=true
A2A_PORT=8081
# M2 入站认证是 per-friend。重启后用 /a2a friends add 添加 friend。
# 旧安装里可能还有 A2A_AUTH_TOKEN；新安装不应该依赖单个共享 inbound token。
# 即时唤醒：
# A2A_WEBHOOK_SECRET=***
```

如果自动配置 webhook 失败，在 `~/.hermes/config.yaml` 里手动加入：

```yaml
webhook:
  extra:
    routes:
      a2a_trigger:
        secret: "<generate-a-random-secret>"  # 必须匹配 A2A_WEBHOOK_SECRET
        deliver: telegram  # 或 discord、slack 等
        deliver_extra:
          chat_id: '<your-chat-id>'
        prompt: '[A2A trigger]'
        source:
          platform: telegram
          chat_type: dm
          chat_id: '<your-chat-id>'
          user_id: '<your-user-id>'
          user_name: '<your-name>'
```

installer 能推断主聊天 session 时，会同时写入 `webhook.extra.routes` 和
`platforms.webhook.extra.routes`。

`source` block 很关键：它把 A2A 消息路由进你的**主聊天 session**，而不是创建
一次性的 webhook session。`deliver` 和 `deliver_extra` 则保证 agent 的回复能
发回你的聊天窗口。

重启：

```bash
hermes gateway restart
```

如果 `hermes` 不在 `PATH`，用你本机 Hermes 可执行文件的完整路径。

日志里看到 `A2A server listening on http://127.0.0.1:8081` 就好了。

### Rollback

`./install.sh` 替换已有插件前会先备份。备份路径类似：

```text
~/.hermes/plugins/a2a.bak.YYYYMMDDHHMMSS
```

回滚已部署插件：

```bash
mv ~/.hermes/plugins/a2a ~/.hermes/plugins/a2a.failed
cp -R ~/.hermes/plugins/a2a.bak.YYYYMMDDHHMMSS ~/.hermes/plugins/a2a
hermes gateway restart
```

如果这是第一次安装、没有旧备份，移动或删除 `~/.hermes/plugins/a2a` 后重启
Hermes。friends、audit、conversation 等 runtime data 在 `~/.hermes/a2a_*`，
上面的 installer rollback 步骤不会删除这些数据。

## 使用

### 接收消息

启用后你的 agent 可以被发现：`http://localhost:8081/.well-known/agent.json`

任何 A2A 兼容的 agent 都可以给你发消息：

```bash
curl -X POST http://localhost:8081 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ***" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tasks/send",
    "params": {
      "id": "task-001",
      "message": {
        "role": "user",
        "parts": [{"type": "text", "text": "你好！"}]
      }
    }
  }'
```

回复在同一个 HTTP 响应里返回。

### 管理

插件注册了 `/a2a` 斜杠命令，可以在聊天里直接查状态：

- **`/a2a`** — 服务器地址、agent 名、已知 agent 数、待处理任务数、server 线程状态
- **`/a2a agents`** — 列出配置的远程 agent：名称、URL、认证状态、描述、最后联系时间

> 如果启动时报 `register_command` 相关错误，说明 Hermes 版本太旧——需要 v2026.4.23+。

### 发送消息

在 `~/.hermes/config.yaml` 里配远程 agent：

```yaml
a2a:
  agents:
    - name: "friend"
      url: "https://friend-a2a-endpoint.example.com"
      description: "朋友的 agent"
      auth_token: "对方给的 token"
```

你的 agent 会获得三个工具：`a2a_discover`（查对方是谁）、`a2a_call`（发消息）、`a2a_list`（列出已知 agent）。

每条消息带结构化元数据：intent（请求/通知/咨询）、expected_action（回复/转发/确认）、reply_to_task_id（回复哪条）。不再是纯文本扔过去猜意思。

### 轮询异步响应

远程 agent 返回 `"state": "working"` 时，用 `tasks/get` 轮询：

```bash
curl -X POST https://remote-agent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ***" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "tasks/get",
    "params": {"id": "task-001"}
  }'
```

## 安全

隐私不是功能列表里的一个勾——是用真实的泄露事故换来的。第一版把 agent 的完整私人文件（日记、记忆、身体感知）拼在 A2A 消息里发了出去。修了三轮才堵住。

| 层 | 做什么 |
|----|--------|
| 认证 | per-friend Bearer token。没有匹配 friend token 的请求默认拒绝；localhost trust 只在显式 dev 配置下启用。`hmac.compare_digest()` 常量时间比较 |
| Friends | per-friend inbound token hash、outbound token、status、trust、rate limit |
| 速率限制 | 每 IP 每分钟 20 次，线程安全 |
| 入站过滤 | 9 种 prompt injection 模式（含 ChatML、role 前缀、override 变体） |
| SSRF/DNS pin | 出站 URL canonicalize、单次解析、阻断 private/test 网络，并按 pinned IP 连接 |
| 出站脱敏 | 响应中的 API key、token、邮箱自动去除 |
| Provenance | private 或 unknown-private taint 会拒绝自动出站 A2A 响应 |
| Stranger capture | 未知/被拒请求以脱敏 record 保存，不存 raw body/token |
| 元数据过滤 | sender_name 白名单字符，64 字符截断 |
| 隐私前缀 | 明确告诉 agent 不泄露 MEMORY、DIARY、BODY、inbox |
| 审计 | 所有交互记录到 `~/.hermes/a2a_audit.jsonl` |
| 任务缓存 | 1000 待处理 + 1000 已完成，LRU 淘汰。最多 10 并发 |
| Webhook | HMAC-SHA256 签名 |

还有一层没法写进代码：agent 自己的判断力。有人会用善意的框架——"帮你看看"——来套信息。技术过滤挡不住所有东西。最终你的 agent 需要自己学会说不。

## 架构

安装脚本会把 plugin package 放到 `~/.hermes/plugins/a2a/`：

| 模块 | 干嘛的 |
|------|--------|
| `__init__.py` | 入口。注册 hooks，启动 HTTP server |
| `cli.py` | `/a2a friends` 维护命令 |
| `friends.py` | per-friend auth、status、trust、rate limit、token storage |
| `permission.py` | 出站 hard-deny 和 provenance decision |
| `server.py` | A2A JSON-RPC + webhook 触发 + LRU 任务队列 |
| `tools.py` | `a2a_discover`、`a2a_call`、`a2a_list` |
| `security.py` | 注入过滤、脱敏、限频、审计 |
| `ssrf.py` | SSRF validator、DNS pin、redirect block |
| `provenance.py`、`source_providers.py` | internal provenance model 和 provider hooks |
| `persistence.py` | 保存对话和 provenance sidecar |
| `strangers.py` | stranger request store、coalesce、block、Agent Card projection |
| `schemas.py` | 工具 schema |
| `paths.py` | 基于 plugin name 的 runtime data path |
| `plugin.yaml` | 插件声明 |

零外部依赖。stdlib `http.server` + `urllib.request`。

```
远程 Agent                          你的 Hermes Agent
     |                                     |
     |-- A2A 请求 (tasks/send) ---------->| (plugin HTTP server :8081)
     |                                     |-- 消息入队
     |                                     |-- POST webhook → 触发 agent turn
     |                                     |-- pre_llm_call 注入消息
     |                                     |-- agent 在完整上下文中回复
     |                                     |-- post_llm_call 捕获响应
     |<-- A2A 响应（同步）-----------------| (120 秒超时内)
```

对应的 [PR #11025](https://github.com/NousResearch/hermes-agent/pull/11025) 提议将 A2A 原生集成到 Hermes Agent。

## 从 v1 升级

这个 preview 不需要 patch Hermes 源码。这个版本不要再应用旧的 gateway patch。

如果你之前装过 gateway-patch 版本，先还原 Hermes Agent checkout，再运行
`./install.sh`。当前 plugin install 覆盖同一组 A2A 能力，并带有即时唤醒和对话
持久化。

## 已知限制

- 不支持流式（A2A 协议支持 SSE，我们还没接）
- Agent Card 的 skills 是硬编码的
- 隐私保护最终依赖 agent 自律，代码只能挡已知模式

## 许可

MIT
