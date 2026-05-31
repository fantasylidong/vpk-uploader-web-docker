# VPK Uploader（服务器版 Only + 中文下载修复 + 自动清理）

- 仅允许 `.vpk` 上传 → 先合规校验（`rules.yml`）。
- 无论管理员/普通用户：上传后**只保留服务器版**（解包→白名单筛选→重打包）。
- **保留 `scripts/vscripts/**` 与 `missions/**`**，避免“没有模式/机关不触发”。
- 下载端点使用 **RFC5987**（`filename*=`）修复**中文文件名 500**。
- 自带兜底清理：临时区 `data/tmp/`、构建残留 `_work_*`。
- SFTP 直接放进 `/app/data/uploads` 的 `.vpk` 会自动登记为管理员上传，永久保存。
- 提供 `/api/thirdparty-maps`，给 NewAnneWeb 查询当前可用图包清单。

## 本地构建
```bash
docker compose up -d --build
# http://localhost:8080
```

## 从 Docker Hub 运行
```bash
docker run -d --name vpk-uploader -p 8080:8080   -e APP_SECRET="change-me" -e ADMIN_USER=admin -e ADMIN_PASS=admin123   -v /opt/vpk-uploader/data:/app/data   yourdockerhubname/vpk-uploader:latest
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
