package main

import (
)
import (
	"net/http/httputil"
	"net/url"
	"net/http"
)

func main() {
	proxy := httputil.NewSingleHostReverseProxy(&url.URL {
		Scheme: "https",
		Host:   "lenta.ru:443",
	})
	http.ListenAndServe(":9090", proxy)
}