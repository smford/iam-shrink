# Multi-stage build for iam-shrink
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/iam-shrink ./cmd/iam-shrink

FROM alpine:3.20

RUN apk --no-cache add ca-certificates bash curl git

COPY --from=builder /bin/iam-shrink /usr/local/bin/iam-shrink
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV AWS_CSM_ENABLED=true
ENV AWS_CSM_PORT=31000
ENV AWS_CSM_HOST=127.0.0.1

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
