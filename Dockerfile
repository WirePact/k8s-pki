FROM golang:1.16-alpine as build

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

LABEL org.opencontainers.image.source=https://github.com/WirePact/k8s-pki \
    org.opencontainers.image.description="This is the PKI for WirePact when run in Kubernetes with the Operator."

WORKDIR /app

ENV GIN_MODE=release \
    PORT=8080 \
    KUBERNETES_SECRET_NAME=wirepact-pki-ca

COPY --from=build /etc/passwd /etc/group /etc/
COPY --from=build /go/bin/app /app/app
COPY tool/docker_entrypoint.sh /app/entrypoint.sh

RUN chown -R appuser:appuser /app && chmod +x /app/entrypoint.sh

USER appuser:appuser

ENTRYPOINT ["/app/entrypoint.sh"]
