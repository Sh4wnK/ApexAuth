# Syntax: docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache protobuf protoc-gen-go protoc-gen-go-grpc
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/apexauth ./cmd/apexauth && \
    go build -o /out/seed ./cmd/seed && \
    go build -o /out/bench ./cmd/bench && \
    go build -o /out/sso-client ./examples/sso-client

FROM alpine:3.22
RUN addgroup -S apexauth && adduser -S apexauth -G apexauth
COPY --from=build /out/apexauth /usr/local/bin/apexauth
COPY --from=build /out/seed /usr/local/bin/seed
COPY --from=build /out/bench /usr/local/bin/bench
COPY --from=build /out/sso-client /usr/local/bin/sso-client
USER apexauth
EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["apexauth"]
