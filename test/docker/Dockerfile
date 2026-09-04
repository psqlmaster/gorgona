# Mesh test node: builds gorgonad from the working tree, so the image always
# carries the code you are about to test. Build context is the repository root:
#   docker compose -f test/docker/docker-compose.yml up -d --build
FROM debian:bookworm-slim AS build
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends gcc libc6-dev make libssl-dev > /dev/null
WORKDIR /src
COPY Makefile ./
COPY common/ ./common/
COPY server/ ./server/
COPY client/ ./client/
RUN make > /dev/null

FROM debian:bookworm-slim
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends libssl3 ca-certificates > /dev/null
COPY --from=build /src/gorgonad /src/gorgona /usr/local/bin/
RUN mkdir -p /etc/gorgona /var/lib/gorgona /var/log/gorgona
WORKDIR /var/log/gorgona
