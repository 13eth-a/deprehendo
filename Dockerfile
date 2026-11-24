# cloud server image for Railway. builds deprehendo-cloud and its analyzer child
# (deprehendo-analyzer, which must sit beside it) from this repository.
#
# go.mod requires go 1.27.4 (standard-library security fixes, 7.60 dependency
# scan). if this image ships an older 1.27.x, go downloads 1.27.4 at build time
# (GOTOOLCHAIN=auto); check that the tag exists
# on docker hub before the first build.
from golang:1.27-bookworm as build
workdir /src
copy go.mod go.sum ./
run go mod download
copy . .
run CGO_ENABLED=0 go build -trimpath -o /out/deprehendo-cloud ./cmd/deprehendo-cloud \
 && CGO_ENABLED=0 go build -trimpath -o /out/deprehendo-analyzer ./cmd/deprehendo-analyzer

from debian:bookworm-slim
# ca-certificates: the server calls the S3-compatible bucket and neon over TLS.
run apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
workdir /app
copy --from=build /out/deprehendo-cloud /out/deprehendo-analyzer ./
# serve applies these migrations itself before listening (7.57).
copy db/migrations ./db/migrations

# run as an unprivileged user (7.60): the server and every analyzer child it
# starts handle hostile bundles, so neither should hold root in the container.
# /app stays root-owned and read-only to it; analyzer children write only
# their private directory under /tmp. A local store (DEPREHENDO_S3_BUCKET unset)
# needs a writable -storage-root, so /app/storage is the one writable path.
run useradd --system --uid 10001 --no-create-home deprehendo \
 && mkdir -p /app/storage && chown deprehendo /app/storage
user deprehendo

# railway injects PORT. everything else comes from railway variables:
#   DATABASE_URL, EXTERNAL_URL, DEPREHENDO_S3_BUCKET, AWS_ENDPOINT_URL_S3,
#   AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
# nothing secret is baked into the image. run one replica only: the policy
# signing secret is per process, so a second replica would reject uploads
# policies the first one issued.
ENV PORT=6080
cmd ["sh", "-c", "exec ./deprehendo-cloud serve -addr 0.0.0.0:${PORT} -database \"${DATABASE_URL}\" -dir db/migrations -external-url \"${EXTERNAL_URL}\""]
