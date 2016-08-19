package rcn

import (
	"net"
	"log"
	"bufio"
	"io"
	"bytes"
	"time"
)

func Mom(conn net.Conn, id   string, tr *StompTransport) (err error) {

	reader := bufio.NewReader(conn)

	tr.MomRegister(id, func(s Stomp) {
		if e := send(s, conn); e != nil {
			log.Printf("sending from stomp to mom error.%v", e)
		}
	})
	defer tr.MomUnregister(id)

	var msg []byte
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	pingFunc := func() {
		for range ticker.C {
			send(Stomp{Cmd:"MESSAGE", Body:map[string]string{"cmd":"ping"}}, conn)
		}
	}

	for {
		if msg, err = reader.ReadSlice(0); err != nil {
			return
		}
		if err = handle(tr, NewStomp(msg), conn, id, pingFunc); err != nil {
			return
		}
	}

}

func handle(tr *StompTransport, stomp Stomp, conn net.Conn, id   string, pingFunc func()) (err error) {
	log.Printf("mom message recieved.\n%v", string(stomp.ToStomp()))
	switch {
	case stomp.Cmd == "SEND" &&  stomp.Body != nil:
		stomp.Body["compositeId"] = id
		err = tr.Send(stomp)
	case stomp.Cmd == "CONNECT" :
		err = send(Stomp{Cmd:"CONNECTED"}, conn)
	case stomp.Cmd == "SUBSCRIBE" :
		go pingFunc()
	default:
		log.Printf("mom: unknow message type: %v", stomp.Cmd)
	}

	return
}

func send(stomp Stomp, conn net.Conn) (err error) {
	b := stomp.ToStomp()
	if p := stomp.Body; p != nil && p["cmd"] != "ping" {
		log.Printf("mom sending\n%v", string(b))
	}
	if _, err = io.Copy(conn, bytes.NewReader(append(b[:], []byte{0}[:]...))); err != nil {
		return
	}
	return
}

