FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o interceptor .

FROM alpine:3.19
RUN apk add --no-cache wget ca-certificates && adduser -u 1000 -D appuser
WORKDIR /app
COPY --from=builder /app/interceptor .
RUN chown appuser:appuser interceptor
USER appuser
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
CMD ["./interceptor"]
