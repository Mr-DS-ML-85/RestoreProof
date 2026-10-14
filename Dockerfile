# RestoreProof image (used for web, worker and scheduler).
# restic, rclone and the Docker CLI are copied from their official, version-pinned (multi-arch) images.
FROM restic/restic:0.18.1 AS restic
FROM rclone/rclone:1.75.2 AS rclone
FROM docker:27.3.1-cli AS dockercli

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=restic /usr/bin/restic /usr/local/bin/restic
COPY --from=rclone /usr/local/bin/rclone /usr/local/bin/rclone
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
# ssh/ssh-keyscan for SFTP destinations; ca-certificates for HTTPS/S3/WebDAV backends.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install ".[postgres]" && useradd --system --uid 10001 --home /app restoreproof

# The web container runs unprivileged. The worker overrides the user so it can talk to the Docker socket
# (see compose.yaml): that is the one privileged component, isolated in its own container.
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health').status==200 else 1)"
ENTRYPOINT ["restoreproof"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
