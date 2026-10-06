# Stage 1: Build binary
FROM golang:1.27.0-alpine AS builder

WORKDIR /src
RUN apk add --no-cache git make ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 make build

# Stage 2: Runtime image
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /src/bin/exposureguard /usr/local/bin/exposureguard

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/exposureguard"]
CMD ["--help"]
