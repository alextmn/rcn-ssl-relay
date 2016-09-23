package rcn

import (
	"net"
	"net/url"
	"net/http"
	"net/http/httputil"
	"fmt"
	"../ttlcache"
	"time"
	"crypto/tls"
	"encoding/hex"
	"log"
)

type rcnProxyChanData struct {
	c net.Conn
	e error
}
type RcnProxy struct {
	ch    chan rcnProxyChanData
	cache *ttlcache.Cache
}

func (p *RcnProxy) Accept() (net.Conn, error) {
	r := <-p.ch
	return r.c, r.e
}
func (p *RcnProxy) Close() (error) {
	log.Println("RcnProxy close: ")
	return nil
}
func (p *RcnProxy) Addr() (net.Addr) {
	log.Println("RcnProxy Addr: ")
	return nil
}

func (p *RcnProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k := hex.EncodeToString(r.TLS.TLSUnique)
	if baseUrl, ok := p.cache.Get(k); ok {
		//r.Header.Set("X-Forwarded-Proto", "https")

		log.Printf("proxy request to %v\n", baseUrl)
		started := time.Now()
		url, _ := url.Parse(baseUrl)
		px := httputil.NewSingleHostReverseProxy(url)
		px.ServeHTTP(w, r)
		log.Printf("proxy request done in %v\n", time.Since(started))
	} else {
		log.Printf("no proxy url for %v\n", k)
	}

}

func NewRcnProxy() (p *RcnProxy) {
	p = &RcnProxy{ch : make(chan rcnProxyChanData),
		cache : ttlcache.NewCache(5 * 60 * time.Second),
	}
	go func() {
		log.Println("proxy.Server - Started!")
		http.Serve(p, p)
		log.Println("proxy.Server  - DONE!")
	}()
	return p
}

func (p *RcnProxy) RcnProxyRequest(conn net.Conn, basePath string ) {
	k := key(conn)
	fmt.Printf("k: %v -> %v\n", k, basePath)
	p.cache.Set(k, basePath)
	p.ch <- rcnProxyChanData{conn, nil}
}

func key(conn net.Conn) (string) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		return hex.EncodeToString(tlsConn.ConnectionState().TLSUnique)
	} else {
		return conn.RemoteAddr().String()
	}
}
// http wrapper


