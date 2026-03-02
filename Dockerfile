# Stage 1 with golang img
FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod .
COPY . .
RUN go build -o rawhttp .

# Stage 2 with minimal image
FROM alpine:latest
RUN apk add --no-cache iptables
COPY --from=build /app/rawhttp /rawhttp
CMD iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP && iptables -A INPUT -p icmp -j DROP && /rawhttp
