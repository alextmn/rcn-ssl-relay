package rcn

import (
	"os"
	"encoding/json"
	"log"
	"crypto/sha1"
	"fmt"
	"bytes"
	"crypto/tls"
)

type Config struct {
	Address                string
	Port                   int
	Cert                   string
	RelayInternal          string
	id                     string
	StompAddress           string
	StompPort              int
	StompSSL               bool
	ShowPing               bool
	MomConnectTimeoutSec   int
	ReconnectSec           int
	StalledMsgDropAfterSec int
	SyncMaxResponseSec     int
	RegRelayTimeoutSec     int
}

func NewConfig(fileName string) Config {
	file, _ := os.Open(fileName)
	decoder := json.NewDecoder(file)
	cfg := Config{}

	err := decoder.Decode(&cfg)
	if err != nil {
		log.Printf("error: %v", err)
		panic("coud not load configuration")
	}
	log.Printf("configurtion loaded.\n %+v", cfg)
	return cfg
}

func (c*Config) SetId(cert tls.Certificate) {
	switch {
	case c.StompSSL:
		c.id = "uni-relay-ssl-" + getFingerprint(cert.Certificate[0])
	default:
		c.id = "uni-relay-" + getFingerprint(cert.Certificate[0])
	}

	log.Printf("relay id:  %v", c.id)

}

func getFingerprint(der []byte) string {
	hash := sha1.Sum(der)
	hexified := make([][]byte, len(hash))
	for i, data := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02x", data))
	}
	return string(bytes.Join(hexified, []byte("")))
}

