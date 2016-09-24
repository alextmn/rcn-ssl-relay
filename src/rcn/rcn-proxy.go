package rcn

import (
	"net"
	"net/url"
	"net/http"
	"net/http/httputil"
	"time"
	"errors"
	"log"
)

type rcnProxyChanData struct {
	net.Conn
	e                 error
	done              func()
	nbRead, nbWritten *int64
}

func (w rcnProxyChanData) Read(p []byte) (n int, err error) {
	if n, err = w.Conn.Read(p); err != nil {
		log.Printf("RcnProxy connection closed. %v %v\n", n, err)
		if (w.done != nil) {
			w.done()
			w.done = nil
		}
	}
	*w.nbRead += int64(n)
	return n, err
}
func (w rcnProxyChanData) Write(p []byte) (n int, err error) {
	n, err = w.Conn.Write(p)
	*w.nbWritten += int64(n)
	return
}

type RcnProxy struct {
	ch                chan rcnProxyChanData
	basePath          string
	onRequestFinished func(r *http.Request, started time.Time)
}

func (p *RcnProxy) Accept() (net.Conn, error) {
	r := <-p.ch
	return r, r.e
}
func (p *RcnProxy) Close() (error) {
	//	fmt.Println("RcnProxy close: ")
	return nil
}
func (p *RcnProxy) Addr() (net.Addr) {
	//	fmt.Println("RcnProxy Addr: ")
	return nil
}

func (p *RcnProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	r.Header.Set("X-Forwarded-Proto", "https")
	//r.Header.Set("X-Forwarded-By", "ikey-away.ru")
	r.Header.Set("employeenumber", "23602677")

	//log.Printf("proxy request to %v\n", r.RequestURI)
	started := time.Now()
	url, _ := url.Parse(p.basePath)
	px := httputil.NewSingleHostReverseProxy(url)
	px.ServeHTTP(w, r)
	log.Printf("proxy request %v done in %v\n", r.RequestURI, time.Since(started))
	p.onRequestFinished(r, started)
}

func RcnProxyRequest(conn net.Conn, stompTr *StompTransport, cId string, basePath string) (nbRead, nbWritten int64) {

	log.Printf("RcnProxyRequest started to %v", basePath)
	p := &RcnProxy{
		ch : make(chan rcnProxyChanData, 1),
		basePath : basePath,
		onRequestFinished : func(r *http.Request, started time.Time) {
			sendProxyUrl(stompTr, cId, basePath, r.RequestURI, started,  conn.RemoteAddr())
		},
	}

	chData := rcnProxyChanData{conn, nil, func() {
		p.ch <- rcnProxyChanData{conn, errors.New("connection closed"), nil, &nbRead, &nbWritten }
	}, &nbRead, &nbWritten }
	p.ch <- chData
	http.Serve(p, p)
	log.Printf("RcnProxyRequest done to %v bytes: %v/%v", basePath, nbRead, nbWritten)
	return
}


// http wrapper


