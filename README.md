# VPK Uploader（服务器版 Only + 中文下载修复 + 自动清理）

- 支持 `.vpk`、`.zip`、`.rar`、`.7z` 上传；压缩包内的 `.vpk` 会批量合规校验并生成服务器版。
- 管理员后台可修改单文件上传上限、压缩包内 VPK 数量上限、普通用户保存时间、上传总容量；`MAX_UPLOAD_MB`、`MAX_ARCHIVE_VPK_COUNT`、`DEFAULT_GUEST_TTL_HOURS`、`MAX_TOTAL_UPLOAD_MB` 作为未保存后台设置时的默认值。
- 无论管理员/普通用户：上传后**只保留服务器版**（解包→白名单筛选→重打包）。
- **保留 `scripts/vscripts/**` 与 `missions/**`**，避免“没有模式/机关不触发”。
- 下载端点使用 **RFC5987**（`filename*=`）修复**中文文件名 500**。
- 自带兜底清理：临时区 `data/tmp/`、构建残留 `_work_*`。
- SFTP 直接放进 `/app/data/uploads` 的 `.vpk` 会自动登记为管理员上传，永久保存。上传器启动后会在后台立即扫描，并默认每 60 秒补扫一次；扫描逐文件提交且可重复执行，不会阻塞健康检查和聚合 API。
- 提供 `/api/thirdparty-maps`，给 NewAnneWeb 查询当前可用图包清单。
- 管理员登录后可进入 `/admin/docker`，查看全部容器的状态、CPU、内存、网络、磁盘 I/O、挂载信息和容器文件目录，并执行启动、停止、重启。
- 可由 NewAnneWeb 聚合多个上传节点的文件、容量、Docker 信息和 srcds 状态；本项目提供受 Token 保护的 federation API。
- 聚合上传可以按内网组自动复制：公网文件只进入一个种子节点，种子节点生成服务器版 VPK 后通过内网同步到同组节点；容量不足的节点会跳过，不影响其他节点。

## 本地构建
```bash
docker compose up -d --build
# http://localhost:8080
```

Docker 管理依赖将宿主机 `/var/run/docker.sock` 挂载到容器。仓库内的 Compose 文件已配置该挂载；它等同于授予应用宿主机 Docker 管理权限，请仅向可信管理员开放后台。

## NewAnneWeb 聚合接入

每个被管理节点设置自己的名称和一段高强度随机 Token：

```env
INSTANCE_NAME=上海节点
FEDERATION_API_TOKEN=请替换为至少32字节的随机值
FEDERATION_ALLOWED_CIDRS=NewAnneWeb服务器公网IP/32
```

重启节点后，在 NewAnneWeb 的“三方图设置”中编辑对应上传入口，填写相同的 `FEDERATION_API_TOKEN`，再进入独立的“聚合管理”页面。NewAnneWeb 通过服务端请求节点 API，Token 不会发送到浏览器。每个节点建议使用不同 Token。

### 同内网上传一次并分发

内网复制只会由 `POST /api/federation/uploads` 触发。普通用户的 `/upload`、管理员后台上传和 SFTP 导入仍只写入当前节点，不会意外扩散。

同组节点需要配置相同的 `LAN_GROUP` 和 `LAN_PEER_API_TOKEN`，每台机器使用不同的 `LAN_NODE_ID`，并在 `LAN_PEERS` 中填写其他机器的内网地址。上传器不会根据公网 IP 猜测内网；只有配置为同组、Token 验证通过、节点 ID 匹配且内网地址实际可达时才会复制。

例如三台机器的内网地址分别是 `10.20.0.11`、`10.20.0.12`、`10.20.0.13`，节点 A 的 `.env` 可以写成：

```env
LAN_REPLICATION_ENABLED=1
LAN_NODE_ID=shanghai-a
LAN_GROUP=shanghai-lan
LAN_PEER_API_TOKEN=请替换为至少32字符的同组随机密钥
LAN_PEER_ALLOWED_CIDRS=10.20.0.0/24
LAN_PEERS=[{"id":"shanghai-b","name":"上海 B","url":"http://10.20.0.12:8080"},{"id":"shanghai-c","name":"上海 C","url":"http://10.20.0.13:8080"}]
LAN_DISK_RESERVE_MB=1024
```

节点 B、C 使用各自的 `LAN_NODE_ID`，并把另外两台机器写进 `LAN_PEERS`。这样无论 NewAnneWeb 选择哪台作为上传入口，它都能成为本次种子节点。

安全和容量规则：

- `LAN_PEER_API_TOKEN` 是内网组共享密钥，至少 32 个字符；不要与每个节点自己的 `FEDERATION_API_TOKEN` 共用。
- `LAN_PEER_ALLOWED_CIDRS` 必填，应用只读取 TCP 来源地址，不信任 `X-Forwarded-For`。如果中间经过反向代理，填写代理实际连接上传器时使用的内网地址。
- `LAN_PEERS` 默认只允许 IP 字面量或域名解析到私网、回环或链路本地地址。确需跨公网复制时才能设置 `LAN_ALLOW_PUBLIC_PEERS=1`，并应同时使用 HTTPS。
- `LAN_DISK_RESERVE_MB` 默认保留 1024 MB 物理磁盘空间。节点可用容量取“后台上传总配额剩余”和“物理磁盘安全余量”的较小值。
- 接收节点先按最终服务器版 VPK 的确切大小申请持久化容量预留，再传输文件。预留期间本地上传也会计入这部分空间，避免并发超额。
- 文件使用 SHA-256 去重和校验，写入完成前使用隐藏临时文件，校验通过后原子改名。已经存在的文件不会重复占用空间。
- 一个节点容量不足时返回 `skipped_capacity`，种子节点仍会继续同步其他节点。网络失败和容量跳过都会写入 federation 上传响应的 `replication.peers`。

相关可选项：

```env
LAN_PEER_CONNECT_TIMEOUT_SECONDS=4
LAN_PEER_TRANSFER_TIMEOUT_SECONDS=1800
LAN_RESERVATION_TTL_SECONDS=3600
LAN_REPLICATION_RETRIES=1
LAN_MAX_PARALLEL_PEERS=3
LAN_PEER_TLS_VERIFY=1
```

内网复制接口位于 `/api/lan/replication/`，不使用 federation Token。不要把这些接口放到不受防火墙约束的公网入口。

没有域名或 HTTPS 时，可以直接填写 `http://公网IP:端口`。此时必须把 `FEDERATION_ALLOWED_CIDRS` 配成 NewAnneWeb 的固定出口公网 IP，例如 `203.0.113.8/32`；多台管理端可以用逗号分隔。节点只读取 TCP 连接来源，不信任 `X-Forwarded-For`。这种方式可以阻止其他公网地址访问聚合 API，但 HTTP 内容仍是明文，不要在容器命令或 RCON 命令中直接输入新的密码、Token 等敏感值。

可用下面的命令生成 Token：

```bash
openssl rand -hex 32
```

## 从 Docker Hub 运行
```bash
docker run -d --name vpk-uploader -p 8080:8080   -e APP_SECRET="change-me" -e ADMIN_USER=admin -e ADMIN_PASS=admin123   -v /opt/vpk-uploader/data:/app/data   -v /var/run/docker.sock:/var/run/docker.sock   yourdockerhubname/vpk-uploader:latest
```

## GitHub Actions → Docker Hub
仓库 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`；推到 main 或打 tag 自动推送多架构镜像。

## 目录说明
- `/app/data/uploads`：最终服务器版 VPK；也可通过 SFTP 直接放入 `.vpk`，系统会按管理员上传自动登记
- `/app/data/tmp`：上传临时文件（流程结束即删，附兜底清理）

`SFTP_IMPORT_MIN_AGE_SECONDS` 默认是 30 秒，避免登记仍在写入的文件；`SFTP_SCAN_INTERVAL_SECONDS` 默认是 60 秒，可调整后台补扫间隔，最小为 5 秒。

## NewAnneWeb 对接接口
上传服务只负责告诉 NewAnneWeb 当前有哪些可用图包，不维护“哪些服务器安装了哪些图”。服务器维度由 NewAnneWeb 自己处理。

接口地址：`/api/thirdparty-maps`。`PUBLIC_BASE_URL` 可留空，此时接口返回相对路径，由 NewAnneWeb 按节点地址访问。只有反向代理、NAT 外部端口等与实际监听地址不一致时才需要手动设置。

聚合管理使用 Bearer Token 访问 `/api/federation/`。NewAnneWeb 可通过 `POST /api/federation/uploads` 以 multipart 字段 `file` 将 `.vpk`、`.zip`、`.rar` 或 `.7z` 文件上传到指定节点；该接口与 Docker 管理接口一样受 `FEDERATION_API_TOKEN` 和 `FEDERATION_ALLOWED_CIDRS` 双重限制。

返回示例：

```json
{
  "generated_at": "2026-05-31T12:00:00+00:00",
  "public_base_url": "https://your-uploader.example.com",
  "upload_url": "https://your-uploader.example.com/",
  "admin_url": "https://your-uploader.example.com/admin",
  "map_count": 1,
  "maps": [
    {
      "id": 1,
      "name": "死亡中心改版.vpk",
      "original_name": "死亡中心改版.vpk",
      "stored_name": "死亡中心改版_server.vpk",
      "size": 1048576,
      "size_label": "1.00 MB",
      "role": "guest",
      "created_at": "2026-05-31T12:00:00+00:00",
      "expires_at": "2026-06-01T12:00:00+00:00",
      "detail_url": "https://your-uploader.example.com/detail/1",
      "download_url": "https://your-uploader.example.com/d/1",
      "files_url": "https://your-uploader.example.com/api/uploads/1/files"
    }
  ]
}
```
