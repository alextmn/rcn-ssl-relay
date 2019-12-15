package rcn

import (
	"net"
	"io"
	"log"
	"crypto/tls"
	"bytes"
	"../ratelimit"
	"time"
	"strings"
	"strconv"
)

var emptyBuffer = []byte{0, 0, 0, 0, 0}

type sslConnection struct {
	net.Conn
	buf *[]byte
}
// pre buffer to check is the connection is ssl or not
func (w *sslConnection) Read(p []byte) (n int, err error) {
	if w.buf != nil {
		nb := copy(p, *w.buf)
		w.buf = nil
		return nb, nil
	}
	n, err = w.Conn.Read(p)
	return n, err
}

func HandleConnection(con net.Conn, stompTr *StompTransport, tlsConf *tls.Config, cfg Config) {

	var keepConnection bool
	var cId string = ""
	var name string = ""
	remote := con.RemoteAddr()
	var err error
	startedTime := time.Now()

	defer func() {
		if !keepConnection {
			log.Printf("connection %v finised. %v", cId, remote)
			con.Close()
		}
	}()
	//con.SetReadDeadline(time.Now().Add(30 * time.Second))
	//con.SetWriteDeadline(time.Now().Add(30 * time.Second))


	buf := make([]byte, 5)
	io.ReadFull(con, buf)

	var targetConn net.Conn
	var certFunc func(string) (error)
	var isSSL bool

	switch {
	case bytes.Compare(buf, emptyBuffer) == 0 :
		isSSL = false
		log.Printf("non - secured connection %v", remote)
		targetConn = con
		certFunc = func(cert string) (e error) {
			cId, name, e = stompTr.CheckPem(cert, "", remote)
			return
		}
	default:
		isSSL = true
		log.Printf("secured connection %v", remote)

		c := &sslConnection{con, &buf}
		tlsConn := tls.Server(c, tlsConf)
		if err = tlsConn.Handshake(); err != nil {
			log.Printf("handshake failed. %v %v", err, remote)
			return
		}
		targetConn = tlsConn
		var x590Error error
		cId, name, x590Error = stompTr.CheckX509(tlsConn.ConnectionState().PeerCertificates[0], remote)
		certFunc = func(string) (error) {
			return x590Error
		}

		if (strings.Contains(name, "://")) {
			sendForwardStartHst(stompTr, cId, name, remote)
			var nb12, nb21 int64
			err, nb12, nb21 = upForward(name, tlsConn, cfg, tlsConf, stompTr, cId)
			sendForwardClosedHst(stompTr, cId, startedTime, name, nb12, nb21, remote)
			return
		}
	}

	isMom, isBound, boundPort, ss5Error := ss5(targetConn, cfg, certFunc, stompTr.AllocateShortId)

	switch  {
	case ss5Error != nil:
		log.Printf("SS5 connection error. %v", ss5Error)
		return
	case isMom:
		sendForwardStartHst(stompTr, cId, "mom", remote)
		Mom(targetConn, cId, stompTr)
		sendForwardClosedHst(stompTr, cId, startedTime, "mom", 0, 0, remote)
	case !isMom && isBound:
		stompTr.RelayRegister(boundPort, targetConn, cId, isSSL)
		log.Printf("SS5 connection bound, SSL:%v. %v - %v", isSSL, boundPort, remote)
		io.Copy(targetConn, bytes.NewReader([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}))
		keepConnection = true
	case !isMom && !isBound:
		if other, exists := stompTr.RelayRetrieve(boundPort); exists {
			log.Printf("Start relaying , SSL:%v. (%v) %v - %v", isSSL, boundPort, other.conn.RemoteAddr(), remote)

			sendRelayStartHst(stompTr, cId, other.cId, cId, other.conn.RemoteAddr(), remote, false, isSSL)
			c12nb, c21, started := relay(other.conn, targetConn, 0);
			log.Printf("bound relay finished %v/%v bytes in %s (%v)", c12nb, c21, time.Since(started), remote)
			sendRelayCloseHst(stompTr, cId,  other.cId, cId, other.conn.RemoteAddr(),
				remote, other.isSsl, isSSL, c12nb, c21, started)

		} else {
			log.Printf("Could not start relaying, SSL:%v. (%v)  %v", isSSL, boundPort, remote)
		}
	default:
		log.Printf("error: no action for connection %v", remote)

	}

}

func upForward(name string, conn *tls.Conn, cfg Config, tlsConf *tls.Config, stomp *StompTransport, cId string) (err error, c12nb, c21 int64) {
	var up net.Conn
	switch {
	case strings.HasPrefix(name, "relay://"):
		address := cfg.StompAddress + ":" + strconv.Itoa(cfg.StompPort)
		up, err = net.Dial("tcp", address)
	case strings.HasPrefix(name, "http://"):
		//up, err = net.Dial("tcp", name[7:len(name)])
		log.Printf("forwarding request to :%v", name)
		c12nb, c21 = RcnProxyRequest(conn, stomp, cId, name)
		return nil, c12nb, c21
	case strings.HasPrefix(name, "https://"):
		//up, err = tls.Dial("tcp", name[8:len(name)], tlsConf)
		log.Printf("forwarding request to :%v", name)
		c12nb, c21 = RcnProxyRequest(conn, stomp, cId, name)
		return nil, c12nb, c21
	default:
		log.Printf("the url %v is not implemented", name)
		return
	}
	if (err != nil) {
		log.Printf("up stomp connection to stomp service failed:%v", err)
		return
	}

	c12nb, c21, started := relay(conn, up, 0);
	log.Printf("forward relay finished. %v : %v/%v bytes in %s (%v)", name, c12nb, c21, time.Since(started), up)
	return
}

func rcopy(c1, c2 net.Conn, rate int64) (written int64, err error) {
	switch  {
	case rate > 0:
		// Bucket adding 100KB every second, holding max 100KB
		// e.g ratelimit.NewBucketWithRate(100 * 1024, 100 * 1024)
		return io.Copy(c1, ratelimit.Reader(c2, ratelimit.NewBucketWithRate(float64(rate), rate)))
	default:
		return io.Copy(c1, c2)
	}
}
func relay(c1, c2 net.Conn, rate int64) (c12nb, c21nb int64, started time.Time) {
	started = time.Now()
	ch := make(chan int64)
	go func() {
		nb, _ := rcopy(c1, c2, rate)
		c1.Close()
		c2.Close()
		ch <- nb
	}()
	c21nb, _ = rcopy(c2, c1, rate)
	c1.Close()
	c2.Close()
	c12nb = <-ch
	return
}


