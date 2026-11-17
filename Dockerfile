# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/fresp/nexsland-server/internal/server.Version=${VERSION}" \
      -o /out/nexsland-server ./cmd/nexsland-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nexsland-server /usr/local/bin/nexsland-server
# Owned by the nonroot user so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 /out/data /data
ENV NEXSLAND_DB=/data/nexsland.db \
    NEXSLAND_LISTEN=:8080
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["nexsland-server", "healthcheck"]
ENTRYPOINT ["nexsland-server"]
CMD ["serve"]
