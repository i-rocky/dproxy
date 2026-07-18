# syntax=docker/dockerfile:1
# Release/test-only build. Normal dproxy execution pulls the published digest.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/gateway ./cmd/gateway

FROM scratch
COPY --from=build /out/gateway /gateway
USER 0:0
ENTRYPOINT ["/gateway"]
