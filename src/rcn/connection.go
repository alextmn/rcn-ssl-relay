package rcn

import (
	"net"
	"io"
	"log"
	"crypto/tls"
	"bytes"
	"./../ratelimit"
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
	remote := con.RemoteAddr()
	var err error

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
			cId, e = stompTr.CheckPem(cert, remote)
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
		cId, x590Error = stompTr.CheckX509(tlsConn.ConnectionState().PeerCertificates[0], remote)
		certFunc = func(string) (error) {
			return x590Error
		}

		if (strings.Contains(cId, "up-relay-")) {
			err = upRelay(tlsConn, cfg, tlsConf)
			return
		}
	}

	isMom, isBound, boundPort, ss5Error := ss5(targetConn, cfg, certFunc)

	switch  {
	case ss5Error != nil:
		log.Printf("SS5 connection error. %v", ss5Error)
		return
	case isMom:
		Mom(targetConn, cId, stompTr)
	case !isMom && isBound:
		stompTr.RelayRegister(boundPort, targetConn)
		log.Printf("SS5 connection bound, SSL:%v. %v - %v", isSSL, boundPort, remote)
		io.Copy(targetConn, bytes.NewReader([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}))
		keepConnection = true
	case !isMom && !isBound:
		if c1 := stompTr.RelayRetrieve(boundPort); c1 != nil {
			log.Printf("Start relaying , SSL:%v. (%v) %v - %v", isSSL, boundPort, c1.RemoteAddr(), remote)
			//startRelay(c1, targetConn, stompTr, remote, cfg)
			startRelayLimitRate(c1, targetConn, stompTr, remote, cfg)
		} else {
			log.Printf("Could not start relaying, SSL:%v. (%v)  %v",isSSL, boundPort, remote)
		}
	default:
		log.Printf("error: no action for connection %v", remote)

	}

}

func startRelay(c1, c2 net.Conn, stompTr *StompTransport, remote net.Addr, cfg Config) {
	start := time.Now()
	go func() {
		nb, _ := io.Copy(c1, c2)
		log.Printf("written %v bytes in %s (%v)", nb, time.Since(start), remote)
	}()
	nb, _ := io.Copy(c2, c1)
	log.Printf("read %v bytes in %s (%v)", nb, time.Since(start), remote)


}

func startRelayLimitRate(c1, c2 net.Conn, stompTr *StompTransport, remote net.Addr, cfg Config) {
	// Bucket adding 100KB every second, holding max 100KB
	start := time.Now()
	go func() {
		bucket1 := ratelimit.NewBucketWithRate(100 * 1024, 100 * 1024)
		nb, _ := io.Copy(c1, ratelimit.Reader(c2, bucket1))
		c1.Close()
		log.Printf("written %v bytes in %s (%v)", nb, time.Since(start), remote)
	}()

	bucket2 := ratelimit.NewBucketWithRate(100 * 1024, 100 * 1024)
	nb, _ := io.Copy(c2, ratelimit.Reader(c1, bucket2))
	log.Printf("read %v bytes in %s (%v)", nb, time.Since(start), remote)
	c2.Close()

}

func upRelay(conn *tls.Conn, cfg Config, tlsConf *tls.Config) (err error) {
	var up net.Conn
	address := cfg.StompAddress + ":" + strconv.Itoa(cfg.StompPort)
	switch {
	case cfg.StompSSL:
		up, err = tls.Dial("tcp", address, tlsConf)
	default:
		up, err = net.Dial("tcp", address)
	}
	if (err != nil) {
		log.Printf("up stomp connection to stomp service failed:%v", err)
		return
	}

	start := time.Now()
	go func() {
		nb, _ := io.Copy(conn, up)
		log.Printf("up stomp connection written %v bytes in %s (%v)", nb, time.Since(start), up)
		up.Close()
	}()
	nb, _ := io.Copy(up, conn)
	conn.Close()
	log.Printf("up stomp connection  %v bytes in %s (%v)", nb, time.Since(start), up)

	return

}


