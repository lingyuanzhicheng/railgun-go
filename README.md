# railgun-go

railgun-go 是一个 API 中继服务，用于连接 Cloudflare Workers 和上游机场面板，提供 UUID 验证、在线 IP 管理、ProxyIP 分配等功能。

仍处于测试版本，代码会比较的混乱。请请问LinuxDo查看初始版本说明帖【
基于 Cloudflare Workers 代理的玩法扩展 之 机场面板】后再使用。

声明：
- 本项目的定位是给已有自建机场面板的自建代理用户使用。而非普通Cloudflare Workers代理用户。
- 本项目的作用是起到在XMplus、SSPanel这类机场面板中添加Workers代理用的。而非在Workers中实现机场面板的功能。
- 本项目也并非代理服务，是一个Cloudflare Workers代理与机场面板中间的一个中间层。
- 本项目需要用户已经了解自建机场、Cloudflare Workers代理。这样更容易理解相关部分。

## 功能特性

- **UUID 验证**：验证用户 UUID 并检查 IP 配额
- **在线 IP 管理**：记录和管理用户在线 IP
- **ProxyIP 分配**：支持多种 ProxyIP 获取方式
  - 直接指定具体的 ProxyIP
  - 根据地区代码获取 ProxyIP
  - 随机分配 ProxyIP
- **面板集成**：支持 XMPlus 和 SSPanel 面板
- **数据库支持**：支持 SQLite 和内存缓存
- **定时任务**：支持 ProxyIP 定时同步和检查

## 配置文件

### config.json

主配置文件，位于 `config/config.json`：

**配置项说明：**

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `authkey` | API 认证密钥 | - |
| `port` | 监听端口 | 8080 |
| `base` | API 基础路径 | / |
| `data` | 数据库类型（sqlite/cache） | sqlite |
| `panel.type` | 面板类型（xmplus/sspanel） | - |
| `panel.url` | 面板 URL | - |
| `panel.key` | 面板 API 密钥 | - |
| `proxyip.type` | ProxyIP 类型（local/remote） | local |
| `proxyip.data` | ProxyIP 数据库类型（sqlite/cache） | sqlite |
| `proxyip.cron` | 定时任务 Cron 表达式 | 0 12 */3 * * |
| `proxyip.remote` | 远程 ProxyIP 数据库 URL | - |
| `proxyip.check.url` | ProxyIP 检查 URL | - |
| `proxyip.check.key` | ProxyIP 检查密钥 | - |
| `proxyip.check.mode` | 检查模式（valid/full） | valid |

### railgun.json

节点配置文件，位于 `config/railgun.json`：ID值由面板生成后再填写。

**配置项说明：**

| 环境变量 | 说明 | 必填 |
|----------|------|------|
| `id` | 上游机场面板对应的节点 ID | 是 |
| `name` | 节点名称 | 可随意 |
| `type` | 面板类型（xmplus/sspanel） | 是 |
| `url` | 面板 URL | 是 |
| `key` | 面板 API 密钥 | 是 |

## Workers 配置

将 `workers.js` 部署到 定的Cloudflare Worke，需要配置以下环境变量：

| 环境变量 | 说明 | 必填 |
|----------|------|------|
| `id` | 上游机场面板对应的节点 ID | 是 |
| `railgun` | railgun-go 服务的连接地址 | 是 |
| `authkey` | railgun-go 服务的认证密钥 | 是 |
| `URL302` | 自定义 302 跳转目标地址 | 否 |
| `AccountID` | Cloudflare AccountID（用于 /requests 端点） | 否 |
| `APIToken` | Cloudflare API Token（用于 /requests 端点） | 否 |

## ProxyIP 使用方式

Workers 支持三种 ProxyIP 获取方式：

### 1. 直接指定 ProxyIP

路径：`/proxyip://IP:端口`

- 直接使用指定的 ProxyIP
- 不向 API 发送 ProxyIP 请求
- 示例：`/proxyip://1.2.3.4:443`

### 2. 按地区代码获取

路径：`/proxyip=地区代码`

- 向 API 发送地区代码
- API 返回该地区的 ProxyIP
- 示例：`/proxyip=US`（获取美国地区的 ProxyIP）

### 3. 随机获取

路径：`/`

- 向 API 发送空的 ProxyIP 请求
- API 返回随机的 ProxyIP

## API 接口

**请求：**

```
POST /api/{id}?key={authkey}
Content-Type: application/json

{
  "uuid": "用户UUID",
  "ip": "用户IP地址",
  "proxyip": "地区代码（可选）"
}
```

**响应：**

```json
{
  "auth": true,
  "proxyip": "1.2.3.4:443"
}
```

## 项目结构

```
railgun-go/
├── config/              # 配置文件目录
│   ├── config.json      # 主配置文件
│   ├── railgun.json     # 节点配置文件
│   └── railgun.db       # SQLite 数据库
├── database/            # 数据库模块
│   ├── cache.go         # 内存缓存实现
│   └── sqlite.go        # SQLite 实现
├── proxyip/             # ProxyIP 模块
│   ├── database/        # ProxyIP 数据库
│   ├── proxyip.go       # ProxyIP 逻辑
│   └── database.go      # ProxyIP 数据库接口
├── panel/               # 面板集成
│   ├── xmplus.go        # XMPlus 面板
│   └── sspanel.go       # SSPanel 面板
├── api.go               # API 服务
├── config.go            # 配置加载
├── database.go          # 数据库初始化
├── main.go              # 主程序入口
├── workers.js           # Cloudflare Workers 脚本
├── Dockerfile           # Docker 镜像构建
└── docker-compose.yml   # Docker Compose 配置
```