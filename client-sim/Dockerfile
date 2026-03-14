FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o client-sim .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/client-sim .
EXPOSE 9000
CMD ["./client-sim"]