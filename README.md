# hw2api-gateway

华为云 CodeArts Snap 反向代理网关：多账号池 + OpenAI 兼容 API + 控制面板。

把一批 CodeArts 账号凭据变成一个标准的 `OpenAI /v1` 端点——多号轮换（LRU）、会话粘性、错误冷却、token 自动续期、每日签到领积分，全部内置。自带 Web 控制台：账户池状态/余额、请求日志、模型目录、API Key 管理、账户手动导入。

## 特性

**网关（Go）**
- OpenAI 兼容：`/v1/chat/completions`（流式/非流式/工具调用）、`/v1/models`
- 多账号池：LRU 轮换 + 冷却状态机（软冷却 60s / 错误熔断 10m）+ 单号并发闸
- 会话粘性：同 `conversation_id` 锁定同账号，prompt cache 命中率最大化
- 凭据自动续期：refresh_token 轮换 + PKCE + DPoES ES256 proof，到期前 30 分钟提前刷新
- 每日签到：每号每日自动领积分
- 官方客户端对齐：完整官方请求头（plugin/ide/kernel/traceid 族）+ SDK-HMAC-SHA256 签名 + 每账号稳定机器指纹
- 热重载：`/admin/api/reload` 增量加载新账号，**不重启进程、不断流**
- 内存优先合并：热重载永不把内存中已轮换的凭据打回磁盘旧值

**面板（FastAPI + 单页前端）**
- 仪表盘：TTFT/缓存命中率/SLA/总剩余积分 实时图
- 账号池：每号状态、剩余积分、消费曲线、签到状态
- **账户手动导入**：文件多选上传或粘贴 JSON，纯添加语义（已存在跳过、绝不覆盖），导入即热重载
- API Key 管理：多把随机 key（`sk-hw2api-…`），可备注/吊销，吊销立即生效
- 请求日志：模型/账号/耗时/首字/token/积分 每条记录
- 登录鉴权：HMAC 会话 cookie，`PANEL_ADMIN_PASSWORD` 环境变量设密码

## 快速开始

### 1. 构建网关

```bash
cd gateway
make linux    # 产出 bin/hw2api（Windows: make windows → hw2api.exe）
```

或直接：

```bash
cd gateway && go build -o hw2api ./cmd/server
```

### 2. 准备账户凭据

凭据是一个 JSON 文件（网关 `auths/` 目录，每号一个）：

```json
{
  "user_id": "01a…",
  "user_name": "138…",
  "refresh_token": "rt-…",
  "access_key_id": "AK…",
  "secret_access_key": "SK…",
  "cloud_dragon_token": "STS…",
  "code_verifier": "PKCE verifier（自动续期必需）",
  "client_id": "vscode-codebot",
  "dpop_private_key": {"kty":"EC","crv":"P-256","x":"…","y":"…","d":"…"}
}
```

必要字段：`user_id / refresh_token / access_key_id / secret_access_key / cloud_dragon_token`。
建议附带 `code_verifier` 与 `dpop_private_key`（网关凭此自动续期；缺了则凭据到期即失效）。

### 3. 启动面板（会自动拉起网关）

```bash
cd panel
pip install -r requirements.txt
PANEL_ADMIN_PASSWORD=你的面板密码 PANEL_AUTOSTART_GW=1 python server.py
# 默认 127.0.0.1:8090；首次启动自动生成主 API Key（打印在日志并写入配置）
```

打开 `http://127.0.0.1:8090` → 登录 → **账号池 → ＋ 导入账户**：选择/粘贴凭据 JSON → 导入即热重载生效。

### 4. 调用（OpenAI 兼容）

```bash
curl http://127.0.0.1:8090/v1/chat/completions \
  -H "Authorization: Bearer sk-hw2api-…" \
  -H "Content-Type: application/json" \
  -d '{"model":"glm-5.2","stream":true,"messages":[{"role":"user","content":"你好"}]}'
```

Key 来源：设置页主 API Key，或「API Keys」卡片生成的任意随机 key。

## CN 网络要求

上游 `snap-access.cn-north-4.myhuaweicloud.com` / `sts.cn-north-4.myhuaweicloud.com` **仅中国大陆 IP 可达**（海外 IP 在 TLS 层被重置）：

- 部署在中国大陆服务器：直连即可（`upstream_proxy` 留空）
- 部署在海外服务器：设置页把 `upstream_proxy` 指向一个 CN 出口 HTTP 代理（如本地隧道 `http://127.0.0.1:3128`），网关所有上游请求经它转发

## 配置

面板配置 `panel/panel_config.json`（首次启动自动生成）：

| 键 | 说明 |
|---|---|
| `gateway.listen` | 网关监听地址（默认 127.0.0.1:7866） |
| `gateway.api_key` | 主 API Key（面板↔网关内部调用 + 运维通道） |
| `gateway.api_keys` | 对外发放的随机 key 列表（面板管理） |
| `gateway.binary` | 网关二进制（Linux `hw2api` / Windows `hw2api.exe`） |
| `gateway.upstream_proxy` | CN 出口代理，空=直连 |

面板环境变量：`PANEL_HOST`（默认 127.0.0.1）、`PANEL_PORT`（默认 8090）、`PANEL_ADMIN_PASSWORD`（登录密码，默认 `admin`）、`PANEL_AUTOSTART_GW=1`（启动时自动拉起网关进程；**同机只跑一个网关实例**，多实例会用同一个 refresh_token 互相轮换踩死账号）。

网关自身配置见 `gateway/config.example.json`（独立裸跑网关时使用）。

## 账户导入语义（重要）

导入是**纯添加**：目标已存在的同名凭据（`codearts-{user_id}.json`）直接跳过，绝不覆盖。refresh_token 是单次有效的——服务器上已轮换的新 token 一旦被旧文件覆盖，该账号即失效。批量脚本同理：只推目标不存在的文件、列不出目标清单就整批放弃、一次要推大量文件先熔断人工确认。

## systemd（生产部署）

```ini
[Unit]
Description=hw2api panel
After=network.target

[Service]
WorkingDirectory=/opt/hw2api/panel
Environment=PANEL_AUTOSTART_GW=1
Environment=PANEL_ADMIN_PASSWORD=你的密码
ExecStart=/usr/bin/python3 /opt/hw2api/panel/server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

反代示例（Caddy，流式场景务必去压缩 + 即时 flush）：

```
api.example.com {
    reverse_proxy 127.0.0.1:8090 {
        flush_interval -1
    }
}
```

## 目录结构

```
gateway/   Go 网关源码（cmd/server 主程序；internal/{pool,upstream,auth,server,scheduler}）
panel/     FastAPI 面板（server.py + static/index.html + hw_sign.py）
```

## License

MIT
