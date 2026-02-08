FROM golang:1.22.2-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o railgun-go .

FROM alpine:latest

RUN apk add --no-cache ca-certificates sqlite

WORKDIR /app

COPY --from=builder /build/railgun-go .

RUN mkdir -p /app/config

EXPOSE 8080

CMD ["./railgun-go"]
