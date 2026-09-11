FROM python:3.11-slim-bookworm

ARG DEBIAN_FRONTEND=noninteractive
# buildx 会自动注入 TARGETARCH；经典构建器留空时回退到 dpkg 的判断。
ARG TARGETARCH
# 国内构建可以用 --build-arg STEAMCMD_URL=... 换成镜像地址。
ARG STEAMCMD_URL=https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Etc/UTC \
    STEAMCMD_DIST=/opt/steamcmd-dist

# steamcmd 只发布 32 位 x86 版本：arm64 镜像照常构建但不含 steamcmd，
# 调用创意工坊下载时会明确报错而不是静默失败。
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates tzdata libarchive-tools; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    if [ "$arch" = "amd64" ]; then \
        apt-get install -y --no-install-recommends curl lib32gcc-s1 lib32stdc++6 lib32z1; \
        mkdir -p "$STEAMCMD_DIST"; \
        curl -fsSL --retry 3 --retry-delay 2 "$STEAMCMD_URL" | tar -xz -C "$STEAMCMD_DIST"; \
        test -f "$STEAMCMD_DIST/steamcmd.sh"; \
        chmod +x "$STEAMCMD_DIST/steamcmd.sh"; \
        apt-get purge -y --auto-remove curl; \
    else \
        echo "steamcmd is x86-only, skipping on $arch"; \
    fi; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
COPY rules.yml /app/rules.yml

RUN mkdir -p /app/data/uploads /app/data/tmp /app/data/steamcmd

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
