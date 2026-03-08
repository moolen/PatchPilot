# syntax=docker/dockerfile:1.7

FROM golang:1.26.1-alpine3.22 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cvefix ./cmd/cvefix

FROM alpine:3.22

SHELL ["/bin/sh", "-euxo", "pipefail", "-c"]
RUN apk add --no-cache ca-certificates git bash curl tar

ARG SYFT_VERSION=v1.34.2
ARG GRYPE_VERSION=v0.104.0
RUN arch="$(uname -m)"; \
	case "$arch" in \
		x86_64) target="linux_amd64" ;; \
		aarch64) target="linux_arm64" ;; \
		*) echo "unsupported architecture: $arch"; exit 1 ;; \
	esac; \
	curl -sSfL "https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/syft_${SYFT_VERSION#v}_${target}.tar.gz" -o /tmp/syft.tgz; \
	tar -xzf /tmp/syft.tgz -C /usr/local/bin syft; \
	curl -sSfL "https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VERSION#v}_${target}.tar.gz" -o /tmp/grype.tgz; \
	tar -xzf /tmp/grype.tgz -C /usr/local/bin grype; \
	rm -f /tmp/syft.tgz /tmp/grype.tgz

COPY --from=builder /out/cvefix /usr/local/bin/cvefix
COPY scripts/action-entrypoint.sh /usr/local/bin/action-entrypoint.sh
RUN chmod +x /usr/local/bin/cvefix /usr/local/bin/action-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/action-entrypoint.sh"]
