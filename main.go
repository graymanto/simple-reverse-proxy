package main

import (
	"crypto/subtle"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"

	"golang.org/x/crypto/acme/autocert"
)

var store = sessions.NewCookieStore([]byte("d0G8zAsKvyK1xIk01lySUy47cm3seJ1Owjxgs4BzhX7kKKT09ZpB3bsngDlR"))

func basicAuth(handler http.Handler, username string, password string, realm string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "sp-session")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		authenticatedRaw := session.Values["authenticated"]

		authenticated, ok := authenticatedRaw.(string)
		if ok && authenticated == "true" {
			log.Println("Existing session found. Authenticate and serve", r.URL)
			handler.ServeHTTP(w, r)
			return
		}

		user, pass, ok := r.BasicAuth()

		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {

			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorised.\n"))
			return
		}

		log.Println("Basic auth passed. Add cookie and serve", r.URL)
		session.Values["authenticated"] = "true"
		session.Save(r, w)

		handler.ServeHTTP(w, r)
	}
}

func listenWithLetsEncypt(listenHost string, sslHostName string, handler http.HandlerFunc) {
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(sslHostName),
		Cache:      autocert.DirCache("certs"),
	}

	server := &http.Server{
		Addr: listenHost,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
		Handler: context.ClearHandler(handler),
	}

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe with lets encrypt: ", err)
	}
}

func main() {
	var listenport int
	var destPort int
	var destHost string
	var letsEncrypt bool
	var scheme string
	var destScheme string
	var sslHostName string
	var user string
	var password string
	var certFile string
	var keyFile string

	flag.IntVar(&listenport, "listenPort", 443, "HTTP port")
	flag.IntVar(&destPort, "destPort", 8080, "Destination HTTP port")
	flag.StringVar(&destHost, "destHost", "localhost", "Destination host")
	flag.BoolVar(&letsEncrypt, "withCert", false, "Specifies if lets encrypt certificate should be generated.")
	flag.StringVar(&scheme, "scheme", "https", "Specifies whether to use http or https")
	flag.StringVar(&destScheme, "destScheme", "http", "Specifies whether to use http or https when proxying")
	flag.StringVar(&sslHostName, "sslHostName", "myserver.com", "Host name for lets encrypt whitelist")
	flag.StringVar(&user, "user", "user", "Name of the user used for authentication")
	flag.StringVar(&password, "password", "password", "Password used for basic authentication")
	flag.StringVar(&certFile, "certFile", "server.crt", "Path to certificate file for manually specified ssl")
	flag.StringVar(&keyFile, "keyFile", "server.key", "Path to key file for manually specified ssl")

	flag.Parse()

	fullDestHost := destHost + ":" + strconv.Itoa(destPort)

	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: destScheme,
		Host:   fullDestHost,
	})

	handler := basicAuth(proxy, user, password, "Authentication error")

	listenHost := ":" + strconv.Itoa(listenport)

	if scheme == "http" {
		err := http.ListenAndServe(listenHost, context.ClearHandler(handler))
		if err != nil {
			log.Fatal("ListenAndServe http: ", destPort, listenHost, err)
		}
		return
	}

	if letsEncrypt {
		listenWithLetsEncypt(listenHost, sslHostName, handler)
		return
	}

	err := http.ListenAndServeTLS(listenHost, certFile, keyFile, context.ClearHandler(handler))
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
