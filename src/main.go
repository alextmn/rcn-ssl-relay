package main

import (
	"net"
	"log"
	"./rcn"
	"strconv"
	"crypto/tls"
	"io/ioutil"
)

func main() {

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	var err error

	cfg := rcn.NewConfig("ssl-conf.json")

	certFile, err := ioutil.ReadFile(cfg.Cert)
	if (err != nil) {
		log.Fatalf("cert read error %v", cfg.Cert)
	}
	log.Printf("loaded certificate:\n%v", string(certFile))
	cert, err := tls.X509KeyPair(certFile, certFile)
	if (err != nil) {
		log.Fatalf("cert could not be loaded %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientAuth: tls.RequireAnyClientCert,
	}

	if (tlsConfig == nil) {
		log.Fatal("ssl init failed")
	}
	stompTr :=rcn.NewStompTransport(cfg)

	endpoint := cfg.Address + ":" + strconv.Itoa(cfg.Port)
	log.Printf("going to listen on %v", endpoint)

	// Start listening for new servers.
	listener, err := net.Listen("tcp", endpoint)

	if err != nil {
		log.Fatalf("unable to start server: %v", err)
	}

	log.Printf("listener started %v", listener.Addr())

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("error during Accept(): %v", err)
		}
		go rcn.HandleConnection(conn, stompTr, tlsConfig, cfg)
	}
}
