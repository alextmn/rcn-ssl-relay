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
	"crypto/tls"
	"strconv"
	"math/rand"
)

const AuthQueue = "/queue/RcnAuthQueue"
const HistQueue = "/queue/RcnHistoryQueue"

var REVOKED = errors.New("REVOKED")

type RelayRegisterRec struct {
	conn  net.Conn
	cId   string
	isSsl bool
}

type StompTransport struct {
	conn         net.Conn
	cfg          Config
	mResponseMap sync.RWMutex
	responseMap  map[string]func(Stomp)
	topic        string
	sendCh       chan Stomp

	mRelayMap    sync.RWMutex
	relayMap     map[string]RelayRegisterRec
}

func NewStompTransport(cfg Config, tlsConf *tls.Config) (*StompTransport) {
	tr := &StompTransport{cfg:cfg,
		responseMap:make(map[string]func(Stomp)),
		sendCh: make(chan Stomp, 1),
		relayMap:make(map[string]RelayRegisterRec) }
	tr.topic = cfg.id

	go tr.StompConnect(cfg, tlsConf)
	return tr
}

func (tr *StompTransport) StompConnect(cfg Config, tlsConf *tls.Config) {
	for {
		tr.startTransport(cfg, tlsConf)
		log.Printf("stomp connection lost, reconnection in %v seconds", cfg.ReconnectSec)
		time.Sleep(time.Duration(cfg.ReconnectSec) * time.Second)
	}
}

func (tr *StompTransport) startTransport(cfg Config, tlsConf *tls.Config) (err error) {
	log.Print("trying to connect to stomp")

	address := cfg.StompAddress + ":" + strconv.Itoa(cfg.StompPort)
	switch {
	case cfg.StompSSL:
		tr.conn, err = tls.Dial("tcp", address, tlsConf)
	default:
		tr.conn, err = net.Dial("tcp", address)
	}

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
		tr.conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.MomConnectTimeoutSec) * time.Second))
		var msg []byte
		msg, err = reader.ReadSlice(0)
		if (err != nil) {
			log.Printf("stomp read error. %v", err)
			return
		}

		tr.handle(NewStomp(msg), cfg)
	}

	return
}

func (tr *StompTransport) Send(stomp Stomp) (err error) {
	if stomp.Body != nil {
		stomp.Body["srcTopic"] = tr.topic
	}
	select {
	case tr.sendCh <- stomp:
	case <-time.After(time.Duration(tr.cfg.StalledMsgDropAfterSec) * time.Second):
		err = errors.New(fmt.Sprintf("message dropped after %v sec of trying to deliver it to stomp\n%#v", tr.cfg.StalledMsgDropAfterSec, stomp))
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

func (tr *StompTransport) handle(stomp Stomp, cfg Config) {
	if p := stomp.Body; p != nil && (p["cmd"] != "ping" || cfg.ShowPing ) {
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
			} else {
				log.Printf("missing connection for id %v", id)
			}
			tr.mResponseMap.RUnlock()
		}
		if id, ok := stomp.Body["requestId"]; ok {
			invoke(id)
		} else if id, ok := stomp.Body["compositeId"]; ok {
			invoke(id)
		}
	case stomp.Cmd == "REVOKED" :
		panic("relay REVOKED")
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
		case <-time.After(time.Second * time.Duration(tr.cfg.SyncMaxResponseSec)):
			err = errors.New("stomp timeout " + id)
		}
	}

	tr.mResponseMap.Lock()
	delete(tr.responseMap, id)
	tr.mResponseMap.Unlock()
	return
}

func (tr *StompTransport)  CheckX509(x509 *x509.Certificate, addr net.Addr) (cId string, name string, err error) {
	var b bytes.Buffer
	certWriter := bufio.NewWriter(&b)
	if err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}); err != nil {
		log.Printf("cant get cert from the client. %v", err)
		return
	}
	certWriter.Flush()
	fingerprint := CalcFingerprint(x509.Raw)
	return tr.CheckPem(string(b.Bytes()), fingerprint, addr)
}
func (tr *StompTransport)  CheckPem(pem string, fingerprint string, addr net.Addr) (cId string, name string, err error) {

	a := strings.Split(addr.String(), ":")
	s := Stomp{Cmd:"SEND",
		Header:map[string]string{"destination":AuthQueue},
		Body:map[string]string{
			"cmd":"checkCert",
			"cert":pem,
			"fingerprint":fingerprint,
			"ep_address":a[0], "ep_port":a[1] }}

	var response Stomp
	if response, err = tr.SyncRequest(s); err == nil {
		var ok bool
		if status, _ := response.Body["confirmed"]; status != "true" {
			err = REVOKED
		} else if cId, ok = response.Body["connectionIdentity"]; !ok {
			err = errors.New(fmt.Sprintf("error: could not get connectionIdentity from payload\n%#v", response))
		}

		if name, ok = response.Body["name"]; !ok {
			name = ""
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
	log.Printf("MomRegister :%v", id)
}

func (tr *StompTransport)  MomUnregister(id string) {
	tr.mResponseMap.Lock()
	delete(tr.responseMap, id)
	tr.mResponseMap.Unlock()
	log.Printf("MomUnregister :%v", id)
}

func (tr *StompTransport) AllocateShortId() (uint16) {
	for i := 0; i < 10; i++ {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		v := r.Intn(64000)
		ok := false

		tr.mRelayMap.Lock()
		if _, e := tr.relayMap[strconv.Itoa(v)]; !e {
			log.Printf("random number for relaying %v", v)
			ok = true;
		}
		tr.mRelayMap.Unlock()

		if ok {
			return uint16(v)
		}

	}
	log.Print("cant generate a random number to bind relay")
	return 0
}

func (tr *StompTransport)  RelayRegister(id string, conn net.Conn, cId string, isSsl bool) {
	tr.mRelayMap.Lock()
	tr.relayMap[id] = RelayRegisterRec{conn, cId, isSsl}
	tr.mRelayMap.Unlock()

	// timeout
	go func() {
		time.Sleep(time.Duration(tr.cfg.RegRelayTimeoutSec) * time.Second)
		if result, exists := tr.RelayRetrieve(id); exists {
			r := result.conn.RemoteAddr()
			log.Printf("timeout %v sec on bound socket, connection closed. %v", tr.cfg.RegRelayTimeoutSec, r)
			result.conn.Close()
		}
	}()
}

func (tr *StompTransport)  RelayRetrieve(id string) (result RelayRegisterRec, exists bool) {
	tr.mRelayMap.Lock()
	result, exists = tr.relayMap[id]
	delete(tr.relayMap, id)
	tr.mRelayMap.Unlock()
	return
}

