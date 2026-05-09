FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/agent  ./cmd/agent

FROM scratch

COPY --from=builder /bin/gateway /gateway
COPY --from=builder /bin/agent  /agent

EXPOSE 443/udp 8080/tcp

ENTRYPOINT ["/gateway"]