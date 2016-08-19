package rcn

import (
	"net"
	"io"
	"log"
	"crypto/tls"
	"bytes"
	"time"
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

var a net.Conn

func HandleConnection(con net.Conn, stompTr *StompTransport, conf *tls.Config) {
	defer con.Close()
	//con.SetReadDeadline(time.Now().Add(30 * time.Second))
	//con.SetWriteDeadline(time.Now().Add(30 * time.Second))

	var err error
	var cId string = ""
	remote := con.RemoteAddr()

	buf := make([]byte, 5)
	io.ReadFull(con, buf)

	if bytes.Compare(buf, emptyBuffer) == 0 {
		log.Printf("non - secured connection %v", remote)
		if err = ss5(con, nil); err != nil {
			log.Printf("non-ssl ss5 error. %v", err)
		}
		////////////////// TODO /////////////////
		if a == nil {
			a = con
			io.Copy(con, bytes.NewReader([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}))
			time.Sleep(20 * time.Second)
			a = nil
		} else {
			log.Printf("!!!!!!!!!!!! moving traffic  %v <-> %v", a.RemoteAddr(), con.RemoteAddr())
			go func() {
				io.Copy(a, con)
			}()
			io.Copy(con, a)
		}
		////////////////// TODO /////////////////

	} else {
		log.Printf("secured connection %v", remote)
		c := &sslConnection{con, &buf}
		tlsConn := tls.Server(c, conf)
		if err = tlsConn.Handshake(); err != nil {
			log.Printf("handshake failed. %v %v", err, remote)
			return
		}
		defer tlsConn.Close()

		var cId string
		var revoked error

		if cId, revoked = stompTr.CheckCert(tlsConn.ConnectionState().PeerCertificates[0], remote); err != nil {
			log.Printf("cert declined. %v", err)
		}
		if err = ss5(tlsConn, revoked); err != nil {
			log.Printf("ss5 error. %v", err)
			return
		}

		Mom(tlsConn, cId, stompTr)

	}

	log.Printf("connection %v finised. %v", cId, remote)
}

