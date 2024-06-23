FROM --platform=linux/amd64 golang:1.22 AS builder

WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY ecr-token-sync.go .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /usr/local/bin/app ecr-token-sync.go && chmod a+x /usr/local/bin/app

FROM --platform=linux/amd64 gcr.io/distroless/static-debian11@sha256:6d31326376a7834b106f281b04f67b5d015c31732f594930f2ea81365f99d60c

COPY --from=builder /usr/local/bin/app /ecr-token-sync
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/ecr-token-sync"]
