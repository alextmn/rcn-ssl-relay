package rcn

import (
	"os"
	"encoding/json"
	"log"
)

type Config struct {
	Address       string
	Port          int
	Cert          string
	RelayInternal string
	id            string
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
	cfg.id = "test-relay1"//uuid()
	log.Printf("configurtion loaded.\n %+v", cfg)
	return cfg
}
