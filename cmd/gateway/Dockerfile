# Deny-first nftables gateway image. Multi-stage so `docker build` is
# self-contained from source; the runtime stage is a scratch filesystem with
# only the static gateway binary. Published to ghcr.io by the gateway-image
# workflow; dproxy doctor pulls and pins it by digest.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /gateway ./cmd/gateway

FROM scratch
COPY --from=build /gateway /gateway
ENTRYPOINT ["/gateway"]
