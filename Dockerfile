# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/Calsoft-Pvt-Ltd/calvigil/cmd.version=${VERSION}" \
      -o /out/calvigil .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates git \
    && addgroup -S calvigil \
    && adduser -S -G calvigil calvigil \
    && mkdir -p /work /usr/local/bin/rules \
    && chown -R calvigil:calvigil /work /home/calvigil

COPY --from=build /out/calvigil /usr/local/bin/calvigil
COPY --from=build /src/rules/semgrep /usr/local/bin/rules/semgrep

USER calvigil
WORKDIR /work

ENTRYPOINT ["calvigil"]
CMD ["--help"]
