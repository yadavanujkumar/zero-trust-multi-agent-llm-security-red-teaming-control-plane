FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o interceptor .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/interceptor .
EXPOSE 8080
CMD ["./interceptor"]