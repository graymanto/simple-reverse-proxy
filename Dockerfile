FROM golang:1.8.1-alpine

RUN mkdir -p /go/src/github.com/graymanto/proxyserver
ADD . /go/src/github.com/graymanto/proxyserver

WORKDIR /go/src/github.com/graymanto/proxyserver

RUN set -ex \
    && apk add --no-cache --virtual .build-deps \
        git

RUN go get
RUN go install github.com/graymanto/proxyserver

RUN apk del .build-deps

ENTRYPOINT /go/src/github.com/graymanto/proxyserver/startProxy.sh

EXPOSE 8081
