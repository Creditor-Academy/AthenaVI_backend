#!/usr/bin/env bash
set -euo pipefail

# Run on EC2 from Jenkins CD (main) or manually after setting env vars.
# Requires: .env.production in DEPLOY_DIR, AWS CLI, Docker, docker compose plugin.

: "${ECR_REGISTRY:?ECR_REGISTRY is required}"
: "${ECR_REPOSITORY:?ECR_REPOSITORY is required}"
: "${IMAGE_TAG:?IMAGE_TAG is required}"

AWS_REGION="${AWS_REGION:-us-east-1}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/athena-vi}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"

cd "${DEPLOY_DIR}"

if [ ! -f .env.production ]; then
  echo "Missing ${DEPLOY_DIR}/.env.production"
  exit 1
fi

IMAGE="${ECR_REGISTRY}/${ECR_REPOSITORY}:${IMAGE_TAG}"

echo "Logging in to ECR (${ECR_REGISTRY})..."
aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin "${ECR_REGISTRY}"

echo "Pulling ${IMAGE}..."
docker pull "${IMAGE}"

echo "Running database migrations (one-off)..."
docker run --rm \
  --env-file .env.production \
  --shm-size=1g \
  --entrypoint npx \
  "${IMAGE}" \
  prisma migrate deploy

echo "Starting application..."
export ECR_REGISTRY ECR_REPOSITORY IMAGE_TAG
docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

echo "Waiting for local health check..."
for attempt in $(seq 1 30); do
  if curl -sf http://127.0.0.1:9000/ >/dev/null; then
    echo "Application is healthy on port 9000"
    exit 0
  fi
  sleep 2
done

echo "Health check failed after 60s"
docker compose -f "${COMPOSE_FILE}" logs --tail=50 api || true
exit 1
