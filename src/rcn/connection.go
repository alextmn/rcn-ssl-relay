package rcn

import (
	"net"
	"io"
	"log"
	"crypto/tls"
	"bytes"
)

var emptyBuffer = []byte{0, 0, 0, 0, 0, 0, 0}

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

func HandleConnection(con net.Conn, stompTr *StompTransport, conf *tls.Config) {
	defer con.Close()
	//con.SetReadDeadline(time.Now().Add(30 * time.Second))
	//con.SetWriteDeadline(time.Now().Add(30 * time.Second))

	var err error
	remote := con.RemoteAddr()

	buf := make([]byte, 7)
	io.ReadFull(con, buf)
	//if (buf == []byte{0, 0, 0, 0, 0, 0, 0}) {
	if bytes.Compare(buf, emptyBuffer) == 0 {
		log.Printf("non - secured connection %v", remote)
		ss5(con)
	} else {
		log.Printf("secured connection %v", remote)
		c := &sslConnection{con, &buf}
		tlsConn := tls.Server(c, conf)
		if err = tlsConn.Handshake(); err != nil {
			log.Printf("handshake failed. %v %v", err, remote)
			return
		}
		defer tlsConn.Close()


		if err = stompTr.CheckCert(tlsConn.ConnectionState().PeerCertificates[0], remote ); err != nil {
			log.Printf("cert declined. %v", err)
			return
		}
		if err= ss5(tlsConn); err !=nil {
			log.Printf("ss5 error. %v", err)
			return
		}


	}

	log.Printf("connection finised %v", remote)
}

