FROM golang:1.17-alpine as build

WORKDIR /app

ENV GOOS=linux \
    GOARCH=amd64 \
    USER=appuser \
    UID=1000

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN go build -ldflags="-w -s" -o /go/bin/app


FROM alpine

ARG BUILD_VERSION
ARG COMMIT_SHA

LABEL org.opencontainers.image.source="https://github.com/WirePact/k8s-pki" \
    org.opencontainers.image.authors="cbuehler@rootd.ch" \
    org.opencontainers.image.url="https://github.com/WirePact/k8s-pki" \
    org.opencontainers.image.documentation="https://github.com/WirePact/k8s-pki/blob/main/README.md" \
    org.opencontainers.image.source="https://github.com/WirePact/k8s-pki/blob/main/Dockerfile" \
    org.opencontainers.image.version="${BUILD_VERSION}" \
    org.opencontainers.image.revision="${COMMIT_SHA}" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.title="WirePact Kubernetes PKI" \
    org.opencontainers.image.description="This is the PKI for WirePact when run in Kubernetes with the Operator. It is responsible to deliver key material to the translators for the communication between services."

WORKDIR /app

ENV GIN_MODE=release \
    PORT=8080 \
    KUBERNETES_SECRET_NAME=wirepact-pki-ca \
    BUILD_VERSION=${BUILD_VERSION}

COPY --from=build /etc/passwd /etc/group /etc/
COPY --from=build /go/bin/app /app/app
COPY tool/docker_entrypoint.sh /app/entrypoint.sh

RUN chown -R appuser:appuser /app && chmod +x /app/entrypoint.sh

USER appuser:appuser

ENTRYPOINT ["/app/entrypoint.sh"]
