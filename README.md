# VPK Uploader (Docker + GitHub Actions → Docker Hub)

一个支持 **.vpk 文件上传**、**到期自动删除**、**管理员面板**、**VPK 内容校验** 的轻量级网站。
- 普通用户：文件**固定 24 小时**后自动删除（可配环境变量）
- 管理员：可自定义有效期（小时）或永久
- 仅允许 `.vpk`，上传前**解析并校验**（基于 `rules.yml`）

## 一、快速启动（本地构建）
```bash
docker compose up -d --build
# 访问 http://localhost:8080
```

## 二、从 Docker Hub 直接运行（拉镜像）
假设镜像名是 `yourdockerhubname/vpk-uploader:latest`（把 `yourdockerhubname` 换成你自己的 Docker Hub 用户名）。

### 方式 A：docker run
```bash
mkdir -p /opt/vpk-uploader/data
# 可选：把本地 rules.yml 放到 /opt/vpk-uploader/rules.yml

docker run -d       --name vpk-uploader       -p 8080:8080       -e APP_SECRET="please-change-to-a-long-random-string"       -e ADMIN_USER="admin"       -e ADMIN_PASS="admin123"       -e MAX_UPLOAD_MB=1024       -e DEFAULT_GUEST_TTL_HOURS=24       -e TZ=Asia/Shanghai       -v /opt/vpk-uploader/data:/app/data       -v /opt/vpk-uploader/rules.yml:/app/rules.yml:ro       yourdockerhubname/vpk-uploader:latest
```

### 方式 B：docker compose（拉镜像运行）
```bash
# 可选：.env 内容如下（示例）
# DOCKER_IMAGE=yourdockerhubname/vpk-uploader:latest
# APP_SECRET=please-change-to-a-long-random-string
# ADMIN_USER=admin
# ADMIN_PASS=admin123
# MAX_UPLOAD_MB=1024
# DEFAULT_GUEST_TTL_HOURS=24
# TZ=Asia/Shanghai

docker compose -f docker-compose.pull.yml up -d
```

## 三、GitHub Actions → Docker Hub
1) 在 GitHub 仓库的 **Settings → Secrets and variables → Actions** 添加：  
   - `DOCKERHUB_USERNAME`：Docker Hub 用户名  
   - `DOCKERHUB_TOKEN`：Docker Hub Access Token（在 Docker Hub 创建）
2) 推送到 `main` 或打 tag（如 `v1.0.0`）：
```bash
git tag v1.0.0
git push origin v1.0.0
```
自动进行 **多架构**（amd64/arm64）构建并推送到：
`docker.io/<DOCKERHUB_USERNAME>/vpk-uploader`

## 四、环境变量
- `APP_SECRET`：加密 Cookie 的密钥（必须换成随机长串）
- `ADMIN_USER` / `ADMIN_PASS`：管理员帐密
- `MAX_UPLOAD_MB`：单文件大小上限，默认 `1024`
- `DEFAULT_GUEST_TTL_HOURS`：公共上传保留小时数，默认 `24`
- `RULES_FILE`：规则文件路径（默认 `rules.yml`）
- `TZ`：时区

## 五、规则（rules.yml）
- `max_size_mb`：VPK 最大体积（MB）
- `require_files`：必须包含的文件（如 `addoninfo.txt`）
- `block_globs`：命中即拒绝的路径/通配符
- `warn_globs`：仅警告（在详情页报告展示）
- `allow_extensions`：允许的扩展名（为空则不限制，仅用于报告）

## 六、数据目录
- `./data/uploads`：已接收的 VPK 文件
- `./data/uploader.sqlite3`：数据库
- `./data/tmp`：上传临时文件
