# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# This is the public trader origin, not a CVM service. It must be deployed on a
# separate host and is intentionally absent from deploy/docker-compose.yaml.
FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436 AS build

WORKDIR /build
COPY package.json package-lock.json ./
# T-03P: trader-host verifies the enclave transport itself, and that code is
# in @darknyx/sdk. The image is no longer trader-host-only, which is a real
# size cost accepted deliberately: a release host that proxies every browser
# order but cannot check who it is talking to is the gap T-03 describes.
COPY packages/client-core/package.json packages/client-core/package.json
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/trader-host/package.json packages/trader-host/package.json
RUN npm ci --workspace @darknyx/client-core \
            --workspace @darknyx/sdk \
            --workspace @darknyx/trader-host
COPY packages/client-core/ packages/client-core/
COPY packages/sdk/ packages/sdk/
COPY packages/trader-host/ packages/trader-host/
RUN npm -w @darknyx/client-core run build \
    && npm -w @darknyx/sdk run build \
    && npm -w @darknyx/trader-host run build \
    && npm prune --omit=dev --workspace @darknyx/client-core \
                            --workspace @darknyx/sdk \
                            --workspace @darknyx/trader-host

FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

ENV NODE_ENV=production \
    DARKNYX_TRADER_LISTEN_HOST=0.0.0.0 \
    DARKNYX_TRADER_PORT=8080
WORKDIR /app
COPY --from=build /build/node_modules node_modules
COPY --from=build /build/packages/client-core/package.json packages/client-core/package.json
COPY --from=build /build/packages/client-core/dist packages/client-core/dist
COPY --from=build /build/packages/sdk/package.json packages/sdk/package.json
COPY --from=build /build/packages/sdk/dist packages/sdk/dist
COPY --from=build /build/packages/trader-host/package.json packages/trader-host/package.json
COPY --from=build /build/packages/trader-host/dist packages/trader-host/dist

RUN groupadd --gid 1101 darknyx-trader \
    && useradd --uid 1101 --gid 1101 --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin darknyx-trader \
    && mkdir -p /srv/darknyx/static /var/lib/darknyx-trader \
    && chown 1101:1101 /var/lib/darknyx-trader

USER 1101:1101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.DARKNYX_TRADER_PORT+'/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "packages/trader-host/dist/bin.js"]
