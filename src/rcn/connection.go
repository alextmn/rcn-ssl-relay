package rcn

import (
	"net"
	"io"
	"log"
	"crypto/tls"
	"bytes"
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

	switch {
	case bytes.Compare(buf, emptyBuffer) == 0 :
		log.Printf("non - secured connection %v", remote)
		targetConn = con
		certFunc = func(cert string) (e error) {
			cId, e = stompTr.CheckPem(cert, remote)
			return
		}
	default:
		log.Printf("secured connection %v", remote)
		c := &sslConnection{con, &buf}
		tlsConn := tls.Server(c, tlsConf)
		if err = tlsConn.Handshake(); err != nil {
			log.Printf("handshake failed. %v %v", err, remote)
			return
		}
		targetConn = tlsConn
		certFunc = func(string) (e error) {
			cId, e = stompTr.CheckX509(tlsConn.ConnectionState().PeerCertificates[0], remote)
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
		log.Printf("SS5 connection bound. %v - %v", boundPort, remote)
		io.Copy(targetConn, bytes.NewReader([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}))
		keepConnection = true
	case !isMom && !isBound:
		if c1 := stompTr.RelayRetrieve(boundPort); c1 != nil {
			log.Printf("Start relaying. (%v) %v - %v", boundPort, c1.RemoteAddr(), remote)
			go func() {
				nb, _ := io.Copy(c1, targetConn)
				log.Printf("write %v %v", nb, remote)
			}()
			nb, _ := io.Copy(targetConn, c1)
			log.Printf("read %v %v", nb, remote)
		} else {
			log.Printf("Could not start relaying. (%v)  %v", boundPort, remote)
		}
	default:
		log.Printf("error: no action for connection %v", remote)

	}


}

