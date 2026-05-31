# VPK Uploader（服务器版 Only + 中文下载修复 + 自动清理）

- 仅允许 `.vpk` 上传 → 先合规校验（`rules.yml`）。
- 无论管理员/普通用户：上传后**只保留服务器版**（解包→白名单筛选→重打包）。
- **保留 `scripts/vscripts/**` 与 `missions/**`**，避免“没有模式/机关不触发”。
- 下载端点使用 **RFC5987**（`filename*=`）修复**中文文件名 500**。
- 自带兜底清理：临时区 `data/tmp/`、构建残留 `_work_*`。
- SFTP 直接放进 `/app/data/uploads` 的 `.vpk` 会自动登记为管理员上传，永久保存。
- 提供 `/api/thirdparty-maps`，给 AnneWeb 后台查询“服务器 → 三方图 → 上传入口”。

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

## 三方图服务器配置
可以用环境变量 `THIRDPARTY_MAP_SERVERS_JSON`，或默认文件 `/app/data/server_maps.json` 配置服务器和已有三方图：

```json
{
  "servers": [
    {
      "id": "anne-2330",
      "name": "Anne 1 服",
      "address": "home.trygek.com:2330",
      "maps": ["死亡中心改版", "坠机险途扩展"]
    }
  ]
}
```

接口地址：`/api/thirdparty-maps`。如需 AnneWeb 后台跳转到外网地址，设置 `PUBLIC_BASE_URL=https://your-uploader.example.com`。
