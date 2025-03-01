FROM node:16 as ui
WORKDIR /build

#COPY .git ./.git
COPY Makefile ./Makefile

# download yarn dependencies
COPY ui/yarn.lock ./ui/yarn.lock
COPY ui/package.json ./ui/package.json
RUN make yarn

# build ui
COPY ./ui/ ./ui/
RUN make build-ui

FROM golang:latest as build
WORKDIR /go/src/github.com/pomerium/pomerium
RUN apt-get update \
    && apt-get -y --no-install-recommends install zip

# cache depedency downloads
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /build/ui/dist ./ui/dist

# build
RUN make build-debug NAME=pomerium
RUN touch /config.yaml
RUN CGO_ENABLED=0 go install -ldflags '-s -w -extldflags -static' github.com/go-delve/delve/cmd/dlv@latest
FROM alpine:latest
ENV AUTOCERT_DIR /data/autocert
WORKDIR /pomerium
RUN apk add --no-cache ca-certificates libc6-compat gcompat iproute2
COPY ./rootCA/rootCA.pem /usr/local/share/ca-certificates/myCA.crt
RUN update-ca-certificates
COPY --from=build /go/src/github.com/pomerium/pomerium/bin/* /bin/
COPY --from=build /config.yaml /pomerium/config.yaml
COPY --from=build /go/bin/dlv /bin
COPY scripts/debug-entrypoint.sh /
ENTRYPOINT [ "/bin/pomerium" ]
CMD ["-config","/pomerium/config.yaml"]
