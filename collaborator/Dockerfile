FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /collaborator ./

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /collaborator /collaborator
EXPOSE 53/udp 9999/tcp 9090/tcp
ENTRYPOINT ["/collaborator"]
