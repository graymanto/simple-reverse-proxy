#! /bin/sh
PORT=${PROXY_LISTENPORT:-8080}
SCHEME=${PROXY_SCHEME:-https}
DESTHOST=${PROXY_DESTHOST:-localhost}
USER=${PROXY_USER:-user}
PASSWORD=${PROXY_PASSWORD:-password}
CERTFILE=${PROXY_CERTFILE:-server.crt}
KEYFILE=${PROXY_KEYFILE:-server.key}

/go/bin/proxyserver --listenport "$PORT" --scheme "$SCHEME" --destHost="$DESTHOST" \
	--user "$USER" --password "$PASSWORD" --certFile "$CERTFILE" --keyFile "$KEYFILE"
