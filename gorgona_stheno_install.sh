#!/usr/bin/env bash
#
# gorgona-install.sh
#
# Installs (first run) or updates the gorgona_stheno container.
# The same script handles both cases:
#   - no container yet  -> creates and starts it (install)
#   - container exists  -> recreates it on the latest image (update)
#
# User data in /etc/gorgona and /var/lib/gorgona is preserved.
#
set -euo pipefail
IMAGE="perynfr/gorgona_stheno:latest"
NAME="gorgona_stheno"
# ---------------------------------------------------------------------------
# 1. Make sure Docker is available
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo ">> Docker is not installed."
  echo ">> Install it first: https://docs.docker.com/engine/install/"
  exit 1
fi
# Make sure the Docker daemon is reachable
if ! sudo docker info >/dev/null 2>&1; then
  echo ">> Docker is installed but the daemon is not running or not reachable."
  echo ">> Try: sudo systemctl enable --now docker"
  exit 1
fi
# ---------------------------------------------------------------------------
# Detect install vs update
# ---------------------------------------------------------------------------
if sudo docker inspect "${NAME}" >/dev/null 2>&1; then
  echo ">> Existing container '${NAME}' found - updating..."
  ACTION="update"
else
  echo ">> Container '${NAME}' not found - performing first install..."
  ACTION="install"
fi
# ---------------------------------------------------------------------------
# Pull the latest image
# ---------------------------------------------------------------------------
echo ">> [${ACTION}] Pulling ${IMAGE}..."
sudo docker pull "${IMAGE}"
# ---------------------------------------------------------------------------
# Remove the old container (if any). Data lives in volumes, not in container
# ---------------------------------------------------------------------------
echo ">> [${ACTION}] Removing old container (if present)..."
sudo docker rm -f "${NAME}" >/dev/null 2>&1 || true
# ---------------------------------------------------------------------------
# Start the new container
# ---------------------------------------------------------------------------
echo ">> [${ACTION}] Starting container..."
sudo docker run -d \
  --name "${NAME}" \
  -p 8000:8000 -p 7777:7777 \
  --restart unless-stopped \
  -v /etc/gorgona:/etc/gorgona \
  -v /var/lib/gorgona:/var/lib/gorgona \
  "${IMAGE}"
# ---------------------------------------------------------------------------
# Clean up dangling images
# ---------------------------------------------------------------------------
echo ">> [${ACTION}] Cleaning up dangling images..."
sudo docker image prune -f
# ---------------------------------------------------------------------------
# Wait for startup and show the banner lines from the logs
# ---------------------------------------------------------------------------
echo ">> [${ACTION}] Waiting for startup..."
sleep 2
sudo docker logs "${NAME}" 2>&1 | grep "#" || true
echo ">> Done (${ACTION}). Container '${NAME}' is running."
