# VPK Uploader（服务器版 Only + 中文下载修复 + 自动清理）

- 支持 `.vpk`、`.zip`、`.rar`、`.7z` 上传；压缩包内的 `.vpk` 会批量合规校验并生成服务器版。
- 浏览器默认使用 4 路并发分片上传，网络中断或页面刷新后可续传；原有整包上传接口继续保留。
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
- 内置 steamcmd，可由 NewAnneWeb 通过 `POST /api/federation/workshop` 触发从 Steam 创意工坊下载物品或合集，下载结果走同一条服务器版流水线入库并参与内网复制。

## 本地构建
```bash
docker compose up -d --build
# http://localhost:8080
```

## 并发分片与断点续传

浏览器上传会先建立带随机凭据的上传会话，再按 8 MB 分片并发传输。已确认写入的分片不会重复发送；网络中断或页面刷新后，在同一浏览器重新选择同一个未修改的文件即可继续。完成处理的结果也可重复查询，避免响应丢失时重复生成服务器版文件。

未完成会话保存在持久化目录 `/app/data/upload_sessions`，默认 48 小时过期。上传成功后会立即删除分片，仅保留很小的完成状态；点击“取消”会立即删除整个会话。管理员上传会话的每个请求都会重新检查管理员登录态。

```env
CHUNK_UPLOAD_SIZE_MB=8
CHUNK_UPLOAD_PARALLELISM=4
CHUNK_UPLOAD_MAX_AGE_HOURS=48
CHUNK_UPLOAD_DISK_RESERVE_MB=512
CHUNK_UPLOAD_MAX_ACTIVE_SESSIONS=64
CHUNK_UPLOAD_MAX_SESSIONS_PER_CLIENT=4
```

并发数限制在 1–8，分片大小限制在 1–32 MB。进行中的会话按完整源文件大小计入上传总容量，并预留 `CHUNK_UPLOAD_DISK_RESERVE_MB` 指定的物理磁盘空间；默认最多同时保留 64 个未完成会话、同一来源最多 4 个。反向代理需要允许 `PUT`、`DELETE`，且单请求 body 上限不能低于分片大小。

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

## Steam 创意工坊导入

节点只负责下载和入库，面向用户的鉴权和界面由 NewAnneWeb 负责；接口和聚合管理一样受 `FEDERATION_API_TOKEN` + `FEDERATION_ALLOWED_CIDRS` 双重保护。

下载可能持续几分钟，接口因此是异步的：`POST` 建任务立刻返回 `job_id`，再用 `GET` 轮询。

```bash
# 建任务：物品 ID、创意工坊链接、合集 ID 可以混着给，items 也接受一行一个的多行文本
curl -X POST https://node.example.com/api/federation/workshop \
  -H "Authorization: Bearer $FEDERATION_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items": ["2547462987", "https://steamcommunity.com/sharedfiles/filedetails/?id=1234567890"],
       "collections": ["900000001"]}'
```

返回 `202` 和任务信息，其中 `status_url` 就是轮询地址：

```json
{
  "ok": true,
  "job_id": "c723f93352a14191a2b79f0a00529594",
  "status": "queued",
  "status_url": "https://node.example.com/api/federation/workshop/c723f9...",
  "request": {"ids": ["2547462987", "1234567890"], "collections": ["900000001"]}
}
```

`GET /api/federation/workshop/{job_id}` 返回逐个物品的状态；`GET /api/federation/workshop?limit=20` 列出最近的任务。任务状态为 `queued` / `running` / `succeeded` / `partial` / `failed`，单个物品状态为 `pending` / `downloading` / `processing` / `succeeded` / `partial` / `failed`：

```json
{
  "job_id": "c723f93352a14191a2b79f0a00529594",
  "status": "partial",
  "item_total": 2,
  "item_counts": {"succeeded": 1, "failed": 1},
  "upload_count": 1,
  "items": [
    {"workshop_id": "2547462987", "state": "succeeded", "title": "某张图",
     "origin": "item", "download_source": "direct",
     "uploads": [{"id": 12, "original_name": "某张图_2547462987.vpk", "download_url": "/d/12"}]},
    {"workshop_id": "1234567890", "state": "failed", "error": "steamcmd 下载失败：..."}
  ],
  "replication": {"peers": []}
}
```

导入默认按**普通用户（无管理员）**的规则入库（`role` 缺省为 `guest`）：

- 保存时间取后台的「普通用户保存时间」（`guest_ttl_hours`，设成 0 表示永久），调用方传的 `ttl_hours` 会被忽略；
- 单文件大小上限和网页上传一样，取后台的「单文件上传上限」（`upload_max_mb`）。

需要按管理员规则长期保留时显式传 `"role": "admin"`，这时 `ttl_hours` 省略或填 `0` 表示永久保留，和管理员上传一致。同一个文件再导入一次会续期：有期限的取更晚的过期时间，永久的保持永久。入库后的文件会出现在 `/api/thirdparty-maps`，并按内网组复制到同组节点。

### 上游可以把直链一起带过来

节点所在机房常常连不上 `api.steampowered.com`（实测三台生产节点里只有一台通），但 UGC CDN `cdn.steamusercontent.com` 三台都通。因此 `POST /api/federation/workshop` 接受一个可选的 `details` 映射：上游（NewAnneWeb）把自己查好的 Steam 元数据带过来，节点就不必访问 Web API，直接走直链下载。

```json
{
  "items": ["3001153036"],
  "details": {
    "3001153036": {
      "file_url": "https://cdn.steamusercontent.com/ugc/.../",
      "filename": "whit.vpk",
      "file_size": 5636096,
      "title": "Whitaker's Weapons Range",
      "consumer_app_id": 550
    }
  }
}
```

`details` 是纯优化，省略时行为不变。节点对带来的每一项都要过校验，任何一项不合格就当没提供、回退去查 Web API：

- `file_url` 必须是 **https**，且主机在 `DIRECT_DOWNLOAD_HOST_SUFFIXES` 白名单内，调用方塞不进任意主机；
- `filename` 必须以 `.vpk` 结尾（否则不算真正的内容文件）；
- `consumer_app_id` 给了就必须等于 `STEAM_WORKSHOP_APPID`。

下载完照样核对 VPK 魔数，拿到非 VPK 一样退回 steamcmd。`site.workshop.accepts_supplied_details` 会告诉上游这个节点支持该字段。

### 两条下载通道

1. **直链**：`file_url` 来自上游带来的 `details`，或者节点自己查 Steam Web API。直接 HTTPS 取回，不需要 steamcmd，arm64 节点也能用。物品内容托管在 SteamPipe 上时 Steam 返回的 `file_url` 会退化成预览图地址，节点会识别出来并跳过这条通道。国内节点连 Steam CDN **单连接会被限速、还常被中途断开**（#58-59 实测 `cdn.steamusercontent.com` 单连接 35～300 KB/s，827 MB 的图在 99 MB 处断过；同一文件 8 路并行能到 6 MB/s，Akamai 老域名 `steamusercontent-a.akamaihd.net` 单连接约 2 MB/s）。所以知道文件大小时，直链下载**切成 16 MB 一段、`STEAM_WORKSHOP_DIRECT_CONNECTIONS` 路并行**（缺省 4），每段在原域名和 `STEAM_WORKSHOP_DIRECT_MIRRORS`（缺省 `steamusercontent-a.akamaihd.net`，逗号分隔，留空只用原域名）之间轮换；某个域名对这份文件返回 4xx 就只用其它域名。每段断了用 Range 从断点接着下，最多 `STEAM_WORKSHOP_DIRECT_ATTEMPTS` 次（缺省 8）；服务器不认 Range 时退回单连接下载。总时长不超过 `STEAM_WORKSHOP_TIMEOUT_SECONDS`，单次读取 60 秒没有数据就算断开。镜像域名也必须在 Steam 下载域白名单里，跳转出白名单一律拒绝。直链最终失败、又没法改用 steamcmd 时，报错里同时写出两边的原因，不会只剩 steamcmd 那一句。
2. **steamcmd**：以匿名身份执行 `workshop_download_item`，覆盖直链拿不到的物品。**注意它依赖 `client-download.steampowered.com` 做自更新，实测三台生产节点全都解析不了这个域名，所以国内机房基本只能靠直链通道。** 节点会探测这个域名能不能连上（见下文 `steamcmd_ready`），连不上时走 steamcmd 的物品直接失败，不再白白重试三轮。

### steamcmd 的两个前提

- **只有 amd64**。steamcmd 仅发布 32 位 x86 版本，`linux/arm64` 镜像照常构建但不含 steamcmd，此时只有直链通道可用，走 steamcmd 的物品会明确报错。
- **需要能访问 `client-download.steampowered.com`**。steamcmd 每次启动都会自更新，这个域名解析不了就会静默退出。节点会把它自己的 `bootstrap_log.txt` 里的失败行拼进错误信息，例如 `steamcmd 退出码 1（Download failed: http error 0 (client-download.steampowered.com/client/steam_cmd_linux)）`，方便直接定位是网络问题。国内机器构建镜像时还可以用 `--build-arg STEAMCMD_URL=<镜像地址>` 换掉 steamcmd 安装包的下载源。

节点启动时和之后每隔 `STEAMCMD_PROBE_TTL_SECONDS`（默认 600 秒）会在后台探测一次 `STEAMCMD_UPDATE_HOST`（默认 `client-download.steampowered.com`）的 443/80 端口，结果放在 `site.workshop.steamcmd_ready`，失败原因在 `steamcmd_error`。`steamcmd_available` 只表示镜像里带了 steamcmd，**上游判断能不能走 steamcmd 应该看 `steamcmd_ready`**。steamcmd 实际运行时因为自更新失败退出，也会立刻把 `steamcmd_ready` 置为 false。

steamcmd 取回的老式物品文件名不一定是 `.vpk`（例如 `*_legacy.bin`），节点会按 VPK 文件头把它认出来；一个都认不出时，报错里会列出实际下载到的文件。

首次调用会把镜像里的 steamcmd 复制到 `/app/data/steamcmd` 再运行，自更新和下载缓存都留在数据卷里，容器重建不用重下。任务串行执行（steamcmd 不支持并发使用同一个安装目录），未完成任务超过 `STEAM_WORKSHOP_MAX_QUEUED_JOBS` 时接口返回 `429`。节点重启会把队列里和执行中的任务标记为 `failed`，需要 NewAnneWeb 重新触发。

### 相关环境变量

```env
STEAM_WORKSHOP_APPID=550
STEAM_WORKSHOP_TIMEOUT_SECONDS=1800
STEAM_WORKSHOP_RETRIES=3
STEAM_WORKSHOP_MAX_QUEUED_JOBS=32
STEAM_WORKSHOP_DIRECT_DOWNLOAD=1
STEAM_WORKSHOP_ENFORCE_APPID=1
STEAM_WORKSHOP_JOB_RETENTION_HOURS=72
STEAM_WORKSHOP_DIRECT_ATTEMPTS=8
STEAM_WORKSHOP_DIRECT_CONNECTIONS=4
STEAM_WORKSHOP_DIRECT_MIRRORS=steamusercontent-a.akamaihd.net
STEAMCMD_UPDATE_HOST=client-download.steampowered.com
STEAMCMD_PROBE_TTL_SECONDS=600
STEAMCMD_PROBE_TIMEOUT_SECONDS=5
```

`STEAM_WORKSHOP_ENFORCE_APPID=1` 时会拒绝 `consumer_app_id` 不是 `STEAM_WORKSHOP_APPID` 的物品，避免误导入别的游戏的内容。单次任务最多 200 个物品，合集最多向下展开 3 层。

注意服务器版流水线只保留 `maps/**`、`scripts/vscripts/**`、`missions/**` 和 `addoninfo.txt`：导入纯素材类物品（语音包、模型皮肤）会得到一个几乎空的 VPK，这个功能针对的是地图包。

## 从 Docker Hub 运行
```bash
docker run -d --name vpk-uploader -p 8080:8080   -e APP_SECRET="change-me" -e ADMIN_USER=admin -e ADMIN_PASS=admin123   -v /opt/vpk-uploader/data:/app/data   -v /var/run/docker.sock:/var/run/docker.sock   yourdockerhubname/vpk-uploader:latest
```

## GitHub Actions → Docker Hub
仓库 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`；推到 main 或打 tag 自动推送多架构镜像。

## 目录说明
- `/app/data/uploads`：最终服务器版 VPK；也可通过 SFTP 直接放入 `.vpk`，系统会按管理员上传自动登记
- `/app/data/tmp`：上传临时文件（流程结束即删，附兜底清理）
- `/app/data/upload_sessions`：断点续传会话与未完成分片（自动过期清理）
- `/app/data/steamcmd`：steamcmd 安装目录、自更新内容和创意工坊下载缓存（物品处理完即删）

`SFTP_IMPORT_MIN_AGE_SECONDS` 默认是 30 秒，避免登记仍在写入的文件；`SFTP_SCAN_INTERVAL_SECONDS` 默认是 60 秒，可调整后台补扫间隔，最小为 5 秒。

## NewAnneWeb 对接接口
上传服务只负责告诉 NewAnneWeb 当前有哪些可用图包，不维护“哪些服务器安装了哪些图”。服务器维度由 NewAnneWeb 自己处理。

接口地址：`/api/thirdparty-maps`。`PUBLIC_BASE_URL` 可留空，此时接口返回相对路径，由 NewAnneWeb 按节点地址访问。只有反向代理、NAT 外部端口等与实际监听地址不一致时才需要手动设置。

聚合管理使用 Bearer Token 访问 `/api/federation/`。NewAnneWeb 可通过 `POST /api/federation/uploads` 以 multipart 字段 `file` 将 `.vpk`、`.zip`、`.rar` 或 `.7z` 文件上传到指定节点，可选字段 `role` 为 `admin`（缺省，永久保存）或 `guest`（按普通用户保存时间过期）；该接口与 Docker 管理接口一样受 `FEDERATION_API_TOKEN` 和 `FEDERATION_ALLOWED_CIDRS` 双重限制。

创意工坊导入走 `POST /api/federation/workshop`，用法见上文。`GET /api/federation/summary` 的 `site.workshop` 里带有本节点的创意工坊能力（`steamcmd_ready`、`direct_download_enabled`、`active_jobs` 等）以及导入默认采用的规则（`default_role`、`upload_max_mb`、`guest_ttl_hours`），NewAnneWeb 可据此决定是否显示导入入口、按多大的上限预检。`site.total_upload_available_bytes` 是扣掉预留空间和磁盘余量之后真正还能装下的字节数。

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
