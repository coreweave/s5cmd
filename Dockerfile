FROM golang:1.22-alpine AS build
ARG VERSION
ARG BUILD
COPY . /s5cmd/
RUN apk add --no-cache git make && \
    cd /s5cmd/ && \
    CGO_ENABLED=0 make build VERSION="${VERSION:-$(cat version.txt)}" BUILD="${BUILD:-dev}"

FROM alpine:3.20
COPY --from=build /s5cmd/s5cmd .
WORKDIR /aws
ENTRYPOINT ["/s5cmd"]
