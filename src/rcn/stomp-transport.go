package rcn

import (
	"net"
	"log"
	"time"
	"bufio"
	"io"
	"bytes"
	"sync"
	"strings"
	"errors"
	"encoding/pem"
	"crypto/x509"
)

type StompTransport struct {
	conn        net.Conn
	cfg         Config
	m, cm       sync.RWMutex
	responseMap map[string]func(Stomp)
	isActive    bool
}

func NewStompTransport(cfg Config) (*StompTransport) {
	tr := &StompTransport{cfg:cfg, responseMap:make(map[string]func(Stomp))}

	go tr.StompConnect()
	return tr
}

func (tr *StompTransport) StompConnect() {
	for {
		tr.startTransport()
		log.Printf("stomp connection lost, reconnection in %v seconds", 5)
		time.Sleep(5 * time.Second)
	}
}

func (tr *StompTransport) startTransport() (err error) {
	log.Printf("trying to connect to stomp %v:%v", "", 55)

	tr.conn, err = net.Dial("tcp", "127.0.0.1:61612")
	if (err != nil) {
		log.Printf("stomp connaction error. %v", err)
		return
	}

	log.Print("connected to stomp")

	tr.send(Stomp{Cmd:"CONNECT",
		Header:map[string]string{"login":"", "passcode":""}})

	reader := bufio.NewReader(tr.conn)
	tr.cm.Lock()
	tr.isActive = true;
	tr.cm.Unlock()
	for {
		tr.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var msg []byte
		msg, err = reader.ReadSlice(0)
		if (err != nil) {
			tr.cm.Lock()
			tr.isActive = false;
			tr.cm.Unlock()

			log.Printf("stomp read error. %v", err)
			return
		}

		tr.handle(NewStomp(msg))
	}

	return
}
func (tr *StompTransport) send(stomp Stomp) (err error) {
	b := stomp.ToStomp()
	log.Printf("senting to stomp\n%v", string(b))

	tr.cm.RLock()
	switch {
	case tr.isActive:
		if _, err = io.Copy(tr.conn, bytes.NewReader(append(b[:], []byte{0}[:]...))); err != nil {
			log.Printf("stomp error while sending. %v", err)
		}
	default:
		err = errors.New("stomp is not active, packet dropped.")
		log.Print(err.Error())
	}
	tr.cm.RUnlock()

	return
}

func (tr *StompTransport) handle(stomp Stomp) {
	log.Printf("stomp message recieved.\n%v", string(stomp.ToStomp()))
	switch {
	case stomp.Cmd == "CONNECTED" :
		s := Stomp{Cmd:"SUBSCRIBE", Header:map[string]string{
			"destination":"/topic/relay-" + tr.cfg.id,
			"ack":"" }}
		tr.send(s)
	case stomp.Cmd == "MESSAGE" &&  stomp.Body != nil:
		if rId, ok := stomp.Body["requestId"]; ok {
			tr.m.RLock()
			if f := tr.responseMap[rId]; f != nil {
				f(stomp)
			}
			tr.m.RUnlock()
		}

	default:
		log.Printf("unknow message type: %v", stomp.Cmd)
	}
}

func (tr *StompTransport)  SyncRequest(stomp Stomp) (response Stomp, err error) {
	c1 := make(chan Stomp, 1)
	defer close(c1)
	id := uuid()
	stomp.Body["requestId"] = id

	tr.m.Lock()
	tr.responseMap[id] = func(s Stomp) {
		c1 <- s
	}
	tr.m.Unlock()

	if err = tr.send(stomp); err == nil {
		select {
		case res := <-c1:
			response = res
		case <-time.After(time.Second * 1):
			err = errors.New("stomp timeout " + id)
		}
	}

	tr.m.Lock()
	delete(tr.responseMap, id)
	tr.m.Unlock()
	return
}

func (tr *StompTransport)  CheckCert(x509 *x509.Certificate, addr net.Addr) (err error) {

	var b bytes.Buffer
	certWriter := bufio.NewWriter(&b)
	if err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}); err != nil {
		log.Printf("cant get cert from the client. %v", err)
		return
	}
	certWriter.Flush()

	a := strings.Split(addr.String(), ":")
	s := Stomp{Cmd:"SEND",
		Header:map[string]string{
			"destination":"/queue/RcnAuthQueue" },
		Body:map[string]string{
			"cmd":"checkCert",
			"cert":string(b.Bytes()),
			"srcTopic:":"/topic/relay-" + tr.cfg.id,
			"ep_address":a[0], "ep_port":a[1] }}

	if _, err = tr.SyncRequest(s); err == nil {
		log.Print("checking response")
	}
	return err
}

