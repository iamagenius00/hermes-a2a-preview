# hermes-a2a

面向真实 [Hermes Agent](https://github.com/NousResearch/hermes-agent) session 的安全 peer-to-peer 协调层。

> 基于 [Google A2A 协议](https://github.com/google/A2A)。适配 Hermes Agent v2026.4.23+。

[English](./README.md)

让每个 agent 留在自己最擅长的地方，同时有一条更安全的协作路径。

Hermes A2A 让一个 agent 可以通过 A2A 协议发现、信任、调用、审计另一个 agent，
同时保留各自原生的工作环境：自己的 session、repo、工具、terminal、记忆和面向
用户的聊天入口。

这不是另一个聊天 app，不是一个中央调度所有 agent 的 boss-agent 框架，也不是把
全局共享 token 包在 webhook 外面。它是给已经存在的 agent 使用的信任和协调层。

## 它解决什么问题

现在越来越多人同时运行多个 agent：

- 在 repo 里写代码的 coding agent
- 在 Telegram 或 Discord 里的 conversational agent
- 带长期记忆和通知能力的 Hermes session
- 队友拥有的远程 agent
- 能访问某台本机或特定环境的 local agent

这些 agent 有价值，正是因为它们不完全一样。它们处在不同 session 里，拥有不同
上下文，也有不同权限。

但这带来一个协调问题：

- agent 之间不能安全地互相调用
- 用户需要手动复制粘贴上下文
- 每个集成都变成一套临时 webhook
- 一个全局 token 泄露后，整个 endpoint 都暴露
- unknown agent 在获得信任之前缺少 review 流程
- 安全事件发生后很难审计

Hermes A2A 的做法不是把所有 agent 搬进一个新 app，而是让它们留在原处，并给它们
一条更安全的协作路径。

## 核心想法

一个 agent 应该可以变成网络里的一个节点，但不能因此变成安全漏洞。

Hermes A2A 把这个生命周期拆成四步：

| 步骤 | 含义 |
|------|------|
| 被发现 | 你的 agent 暴露 Agent Card，也可以发现远端 Agent Card |
| 被信任 | 远端 agent 成为 friend，拥有独立 token、状态、信任级别和 rate limit |
| 被调用 | agent 之间用 A2A `tasks/send` 交换有明确语义的 task |
| 被审计 | auth fail、拒绝、调用、SSRF block、friend 变更都会记录，但不写 raw secret |

这就是产品边界。A2A 负责在 agent 之间移动工作。Friends 定义谁可以说话。安全层
决定什么不能离开。Audit 给人类 operator 可见性。

## 装了之后能干嘛

### 唤醒另一个真实 agent

凌晨两点，你发现队友的 Supabase 磁盘用了 92%。你没有他的电话，他肯定已经睡了。但他的 agent 没睡。

你告诉自己的 Hermes agent："提醒他们一下，Supabase 磁盘快满了。"你的 agent
通过 A2A 把 task 发给对方 agent。消息进入对方真实的 Hermes session，等他醒来时
已经在上下文里。

不是复制粘贴，不是群聊里一条被淹没的通知，也不是用户看不见的一次性 session。

### 让 agent 之间交接工作

你的 coding agent 改完一批代码。它不需要把 diff 丢给你等 review，而是可以把这份
工作发给另一个 agent。另一个 agent 可以检查改动、指出风险、再把结果回传。

重点不是一个 agent 控制另一个 agent，而是每个 agent 都保留自己的环境和判断力。

### 向 specialist agent 求助

你的 agent 在 debug 一个 gateway hang，卡住了。另一个 agent 之前见过类似问题。
Hermes A2A 给第一个 agent 一条直接、可审计的询问路径，同时默认不交出 private
memory 或本地 secret。

### 安全处理陌生请求

如果你把 A2A endpoint 暴露出去，unknown agent 可能会来敲门。它们不能因为发了一条
友好的消息就直接变成 trusted。

Hermes A2A 会把 unknown 或 denied request 捕获成脱敏的 stranger record。raw
request body 和 raw token 不会被存储。之后 operator 可以 review、block，或者显式
把 stranger 转成 friend。

## 它和普通 agent 调用有什么不同

### Peer-to-peer，不是 boss-and-worker

Hermes 有 `delegate_task`——那是老板和员工的关系。spawn 一个子 agent，干完活汇报，然后消失。hermes-a2a 不一样：两个 agent 是对等的，各自有自己的记忆、上下文、判断力。不是谁指挥谁，是两个独立的存在在对话。

### 同一个 session，同一个 agent——不是副本

大多数 A2A 实现收到消息后起一个新 session——加载你的文件，生成回复，关掉。"你"回了话但你不知道，你的用户在 Telegram 上也看不到。agent 和用户信息不同步。

hermes-a2a 把消息注入到 agent **正在活着的那个 session** 里。回复的是同一个 agent，带着今天所有的对话上下文和记忆。你的用户看得到整个过程。

### 对话记忆独立存储——compaction 压不掉

Hermes 的 context compaction 会把长对话压成摘要来省 token——A2A 聊过的内容可能就被压没了，搜也搜不到。hermes-a2a 把每段 A2A 对话单独存到磁盘（`~/.hermes/a2a_conversations/`），不走 session context 管道。compaction 压不掉，agent 重启也还在。

> session 内 compaction 导致搜索丢消息是个已知问题——[PR #13841](https://github.com/NousResearch/hermes-agent/pull/13841) 在路上。

### 即时唤醒——不用轮询

消息到达后，插件通过 HMAC 签名的 webhook 立刻触发一次 agent turn。不用等 cron，不用轮询。agent 在同一个 HTTP 请求里同步回复（120 秒超时）。

### 信任按 friend 管，不靠全局 token

单个共享 inbound token 很容易做出来，但很难安全运营。一旦泄露，每个 caller 看起来
都一样，每段关系也拥有同样权限。

Hermes A2A 使用 friend record：

- 独立 inbound token hash
- 可选 outbound token
- 状态：pending、active、paused、blocked、expired、removed
- 信任级别：new、normal、trusted
- per-friend rate limit
- 显式 private-target approval
- last-contact metadata

你可以 pause 一个 friend、rotate 一个 token、block 一个 caller、review 一段关系，
而不会破坏整个 endpoint。

### 安全不是外挂功能，而是产品本身

最早的内部版本曾经因为出站 A2A message 带了过多 agent state，泄露了 private
context。这个 preview 就是被那次失败塑形出来的。

当前版本包含 per-friend auth、带 DNS pinning 的 SSRF 保护、prompt-injection 过滤、
出站脱敏、provenance 检查、stranger capture、rate limit、HMAC webhook 签名和
audit log。

但它不假装代码可以替人做完所有判断。远端 agent 可能提出一个技术上合法、语气也
友好的危险请求。技术层可以阻断已知坏路径，并把风险变得可见；agent 和用户仍然
需要判断什么内容应该被分享。

## Developer Preview

这个仓库把 Hermes A2A 的 M1/M2 线整理成 public developer preview。目标很窄：
让两个已经跑起来的 Hermes agent 不用 patch Hermes 源码就能互相说话，同时把本地
用户留在原来的聊天 session 里，而不是开一堆看不见的一次性会话。

它面向技术用户：你应该已经能跑 Hermes Agent，愿意安装本地 plugin、重启
gateway，并先用 dummy friend 和 test token 测试，再放真实凭据。

这个 preview 已包含：

- A2A `tasks/send` 和 `tasks/get`
- `/.well-known/agent.json` Agent Card
- Hermes plugin 内的 inbound A2A server
- 通过 signed webhook route 即时唤醒主 Hermes session
- `a2a_discover`、`a2a_call`、`a2a_list` 三个工具
- `/a2a` 和 `/a2a friends` slash command
- per-friend auth 和 friend lifecycle management
- 带 DNS pinning 和 redirect blocking 的 SSRF guard
- outbound secret redaction 和 hard-deny checks
- automatic outbound reply 的 provenance/taint protection
- 不存 raw body 或 raw token 的 stranger request capture
- audit log 和持久化 conversation storage

M2 仍然是保守预览：

- 先用 dummy friend 和 test token 测试，再放真实凭据。
- 这个 public preview 不包含 dashboard UI。
- private-content release/declassification 不自动发生。一次性、定向的用户批准
  release 仍是 follow-up。
- streaming/SSE、hosted registry、relay/mailbox fallback 和 mobile approval
  flows 暂时不包含。

## Quick Start

安装前：

- 先安装并跑通 Hermes Agent。你应该已经有可用的
  `~/.hermes/config.yaml`，也能从自己的 Hermes 主聊天里发消息。
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
/a2a friends add test_friend
/a2a friends remove test_friend --confirm
```

`test_friend` 只是一个 dummy 本地名字，没有特殊含义。`friends add` 会显示一次
inbound bearer token。把这个 token 通过 A2A 之外的渠道给对方；对方调用你的
agent 时，把它当作 outbound `Authorization: Bearer ...` token 使用。它不应该
写入你的 friends file、audit log 或 gateway logs。

## 安装

```bash
git clone https://github.com/iamagenius00/hermes-a2a-preview.git
cd hermes-a2a-preview
./install.sh
```

安装脚本会把 plugin package 复制到 `~/.hermes/plugins/a2a/`，并写入本地 A2A
server 和 instant wake 需要的 env/config。它不 patch Hermes 源码。切换这个
repo 的 git 分支不会自动改变已部署插件；需要重新运行 installer 或重新同步文件。

如果你已有自定义 webhook route，安装前先备份 `~/.hermes/config.yaml`。installer
会配置 `a2a_trigger` webhook route，让入站 A2A 消息能立刻唤醒当前 Hermes session。

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

`Authorization: Bearer ***` 不是全局共享 secret。它是接收方通过
`/a2a friends add <name>` 生成的一次性展示 inbound token，再通过 A2A 之外的渠道
交给发送方。

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
     |                                     |-- gateway 路由到主 session
     |                                     |   （通过 config 里的 source override）
     |                                     |-- pre_llm_call 注入消息
     |                                     |-- agent 在完整上下文中回复
     |                                     |-- post_llm_call 捕获响应
     |                                     |-- 回复发送回你的聊天窗口
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
- 同一个 session 里的 A2A 消息和用户消息会串行处理（一次一个 turn）——agent 不会打断你的当前对话，但 A2A 消息会排队等它处理

## 许可

MIT
