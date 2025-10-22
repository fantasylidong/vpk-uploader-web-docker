# VPK Uploader（仅保留“服务器版”）
- 仅允许 `.vpk` 上传，先做合规校验（`rules.yml`）
- **无论管理员/普通用户**：上传成功后立即**解包并只保留“服务器版”**（按白名单重打包 `_server.vpk`），原文件与客户端版不保留
- 详情页可下载服务器版，显示“校验报告 + 服务器版构建报告”
- 普通用户上传默认 **24 小时**过期；管理员上传可自定义有效期（0=永久）

## 服务器白名单（可改）
`app/vpk_tools.py` → `SERVER_KEEP_GLOBS`
- 默认保留：`maps/*.bsp/nav/txt/cfg/kv/lmp/ain`、`addoninfo.txt`
- 如需保留 vscripts（`scripts/vscripts/**`），可取消注释

## 运行
- 本地构建：`docker compose up -d --build` → `http://localhost:8080`
- Docker Hub 拉取：`docker compose -f docker-compose.pull.yml up -d`（先把镜像名填到 `.env` 或命令行）

## GitHub Actions → Docker Hub
仓库 Secrets：`DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`；推到 main 或打 tag 自动推镜像。
