FROM golang:1.22.2

WORKDIR /api
RUN apt-get update && apt-get install -y ca-certificates

COPY . .
RUN go mod download
RUN go mod verify
RUN go build ./cmd/tokenapi.go
ENTRYPOINT ["./tokenapi", "-d", "-r"]