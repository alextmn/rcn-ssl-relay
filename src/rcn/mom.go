package rcn

import (
	"net"
	"log"
	"bufio"
	"io"
	"bytes"
)

type Mom struct {
	conn net.Conn
	id   string
}

func (m*Mom)ServeMom(conn net.Conn, id   string) (err error) {
	m.conn = conn
	m.id = id
	reader := bufio.NewReader(conn)

	var msg []byte
	for {
		if msg, err = reader.ReadSlice(0); err != nil {
			return
		}
		m.handle(NewStomp(msg))
	}
	return
}

func (m *Mom) handle(stomp Stomp) {
	log.Printf("mom message recieved.\n%v", string(stomp.ToStomp()))
	switch {
	case stomp.Cmd == "CONNECTED" :
		s := Stomp{Cmd:"SUBSCRIBE", Header:map[string]string{
			"destination":"/topic/relay-",
			"ack":"" }}
		m.send(s)
	case stomp.Cmd == "MESSAGE" &&  stomp.Body != nil:


	default:
		log.Printf("mom: unknow message type: %v", stomp.Cmd)
	}
}

func (tr *Mom) send(stomp Stomp) (err error) {
	b := stomp.ToStomp()
	log.Printf("mom sending\n%v", string(b))

	if _, err = io.Copy(tr.conn, bytes.NewReader(append(b[:], []byte{0}[:]...))); err != nil {
		return
	}

	return
}
