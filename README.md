# VPK Uploader (w/ Map Processing)
- 仅允许 `.vpk` 上传，先校验合规
- 管理员上传时可勾选“生成 `_server` / `_client`”，对地图 VPK 进行：
  - 解包 → 服务器版白名单打包（仅保留 `maps/*.bsp/nav/txt/cfg/kv/lmp/ain`、`addoninfo.txt` 等）
  - 解包 → 客户端版完整打包（可按需在 `app/vpk_tools.py` 的 `CLIENT_TRIM_GLOBS` 添加裁剪）
  - 生成文件位于数据目录 `/app/data/uploads`，命名为 `<sha>_<rand>_server.vpk` / `_client.vpk`
  - 详情页可直接下载“服务器版/客户端版”，并显示“地图处理报告”

## 快速开始（本地构建）
```bash
docker compose up -d --build
# http://localhost:8080
```

## GitHub Actions → Docker Hub
设置仓库 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`，推到 `main` 或打 tag 自动推送多架构镜像。

## 从 Docker Hub 运行
```bash
docker run -d       --name vpk-uploader       -p 8080:8080       -e APP_SECRET="change-me"       -e ADMIN_USER="admin"       -e ADMIN_PASS="admin123"       -v /opt/vpk-uploader/data:/app/data       yourdockerhubname/vpk-uploader:latest
```

## 可调参数
- 服务器白名单：`app/vpk_tools.py` → `SERVER_KEEP_GLOBS`
- 客户端裁剪：`app/vpk_tools.py` → `CLIENT_TRIM_GLOBS`
- 合规规则：`rules.yml`
