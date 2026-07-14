# VPK Uploader（服务器版 Only + 中文下载修复 + 自动清理）

- 支持 `.vpk`、`.zip`、`.rar`、`.7z` 上传；压缩包内的 `.vpk` 会批量合规校验并生成服务器版。
- 管理员后台可修改单文件上传上限、压缩包内 VPK 数量上限、普通用户保存时间、上传总容量；`MAX_UPLOAD_MB`、`MAX_ARCHIVE_VPK_COUNT`、`DEFAULT_GUEST_TTL_HOURS`、`MAX_TOTAL_UPLOAD_MB` 作为未保存后台设置时的默认值。
- 无论管理员/普通用户：上传后**只保留服务器版**（解包→白名单筛选→重打包）。
- **保留 `scripts/vscripts/**` 与 `missions/**`**，避免“没有模式/机关不触发”。
- 下载端点使用 **RFC5987**（`filename*=`）修复**中文文件名 500**。
- 自带兜底清理：临时区 `data/tmp/`、构建残留 `_work_*`。
- SFTP 直接放进 `/app/data/uploads` 的 `.vpk` 会自动登记为管理员上传，永久保存。
- 提供 `/api/thirdparty-maps`，给 NewAnneWeb 查询当前可用图包清单。
- 管理员登录后可进入 `/admin/docker`，查看全部容器的状态、CPU、内存、网络、磁盘 I/O、挂载信息和容器文件目录，并执行启动、停止、重启。
- 可由 NewAnneWeb 聚合多个上传节点的文件、容量、Docker 信息和 srcds 状态；本项目提供受 Token 保护的 federation API。

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
```

重启节点后，在 NewAnneWeb 的“三方图设置”中编辑对应上传入口，填写相同的 `FEDERATION_API_TOKEN`，再进入独立的“聚合管理”页面。NewAnneWeb 通过服务端请求节点 API，Token 不会发送到浏览器。每个节点建议使用不同 Token，并通过 HTTPS 连接。

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

## NewAnneWeb 对接接口
上传服务只负责告诉 NewAnneWeb 当前有哪些可用图包，不维护“哪些服务器安装了哪些图”。服务器维度由 NewAnneWeb 自己处理。

接口地址：`/api/thirdparty-maps`。如果 NewAnneWeb 需要拿到完整外网链接，设置 `PUBLIC_BASE_URL=https://your-uploader.example.com`。

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
