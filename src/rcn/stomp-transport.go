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
	"fmt"
)

const AuthQueue = "/queue/RcnAuthQueue"

type StompTransport struct {
	conn         net.Conn
	cfg          Config
	mResponseMap sync.RWMutex
	responseMap  map[string]func(Stomp)
	topic        string
	sendCh       chan Stomp
}

func NewStompTransport(cfg Config) (*StompTransport) {
	tr := &StompTransport{cfg:cfg,
		responseMap:make(map[string]func(Stomp)),
		sendCh: make(chan Stomp, 1) }
	tr.topic = "relay-" + tr.cfg.id

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
	abortCh := make(chan int, 1)
	defer close(abortCh)

	go sender(tr.conn, tr.sendCh, abortCh)

	tr.Send(Stomp{Cmd:"CONNECT", Header:map[string]string{"login":"", "passcode":""}})

	reader := bufio.NewReader(tr.conn)
	for {
		tr.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var msg []byte
		msg, err = reader.ReadSlice(0)
		if (err != nil) {
			log.Printf("stomp read error. %v", err)
			return
		}

		tr.handle(NewStomp(msg))
	}

	return
}

func (tr *StompTransport) Send(stomp Stomp) (err error) {
	if stomp.Body != nil {
		stomp.Body["srcTopic"] = tr.topic
	}
	select {
	case tr.sendCh <- stomp:
	case <-time.After(1 * time.Second):
		err = errors.New(fmt.Sprintf("message dropped after 2 sec of trying to deliver it to stomp\n%#v", stomp))
	}

	return
}

func sender(conn net.Conn, ch chan Stomp, abort chan int) {
	for {
		select {
		case stomp := <-ch:
			b := stomp.ToStomp()
			log.Printf("sending to stomp\n%v", string(b))
			if _, err := io.Copy(conn, bytes.NewReader(append(b[:], []byte{0}[:]...))); err != nil {
				log.Printf("stomp error while sending. %v", err)
				return
			}
		case _, ok := <-abort:
			if (!ok) {
				log.Println("stomp sending chanell has been closed")
				return
			}
		}
	}
}

func (tr *StompTransport) handle(stomp Stomp) {
	if p := stomp.Body; p != nil && p["cmd"] != "ping" {
		log.Printf("stomp message recieved.\n%v", string(stomp.ToStomp()))
	}
	switch {
	case stomp.Cmd == "CONNECTED" :
		s := Stomp{Cmd:"SUBSCRIBE", Header:map[string]string{
			"destination":"/topic/" + tr.topic,
			"ack":"" }}
		tr.Send(s)
	case stomp.Cmd == "MESSAGE" &&  stomp.Body != nil:
		var invoke = func(id string) {
			tr.mResponseMap.RLock()
			if f := tr.responseMap[id]; f != nil {
				f(stomp)
			}
			tr.mResponseMap.RUnlock()
		}
		if id, ok := stomp.Body["requestId"]; ok {
			invoke(id)
		} else if id, ok := stomp.Body["compositeId"]; ok {
			invoke(id)
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

	tr.mResponseMap.Lock()
	tr.responseMap[id] = func(s Stomp) {
		c1 <- s
	}
	tr.mResponseMap.Unlock()

	if err = tr.Send(stomp); err == nil {
		select {
		case res := <-c1:
			response = res
		case <-time.After(time.Second * 10):
			err = errors.New("stomp timeout " + id)
		}
	}

	tr.mResponseMap.Lock()
	delete(tr.responseMap, id)
	tr.mResponseMap.Unlock()
	return
}

func (tr *StompTransport)  CheckCert(x509 *x509.Certificate, addr net.Addr) (cId string, err error) {

	var b bytes.Buffer
	certWriter := bufio.NewWriter(&b)
	if err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}); err != nil {
		log.Printf("cant get cert from the client. %v", err)
		return
	}
	certWriter.Flush()

	a := strings.Split(addr.String(), ":")
	s := Stomp{Cmd:"SEND",
		Header:map[string]string{"destination":AuthQueue},
		Body:map[string]string{
			"cmd":"checkCert",
			"cert":string(b.Bytes()),
			"ep_address":a[0], "ep_port":a[1] }}

	var response Stomp
	if response, err = tr.SyncRequest(s); err == nil {
		var ok bool
		if status, _ := response.Body["confirmed"]; status != "true" {
			err = errors.New(fmt.Sprintf("certificate could not be confirmed. %#v", response))
		} else if cId, ok = response.Body["connectionIdentity"]; !ok {
			err = errors.New(fmt.Sprintf("error: could not get connectionIdentity from payload\n%#v", response))
		}
	}
	return
}

func (tr *StompTransport)  MomRegister(id string, f func(Stomp)) {
	tr.mResponseMap.Lock()
	if _, ok := tr.responseMap[id]; ok {
		panic("aleady have this key in stomp hasmap:" + id)
	}
	tr.responseMap[id] = f
	tr.mResponseMap.Unlock()
}

func (tr *StompTransport)  MomUnregister(id string) {
	tr.mResponseMap.Lock()
	delete(tr.responseMap, id)
	tr.mResponseMap.Unlock()
}

