package rcn

import (
	"time"
	"log"
	"encoding/hex"
	"math/rand"
)

func uuid() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	u := make([]byte, 16)
	_, err := r.Read(u)
	if err != nil {
		log.Panicf("could not generate uuid. %v", err)

	}
	//These lines clamp the values of byte 6 and 8 to a specific range.
	// rand.Read returns random bytes in the range 0-255, which are not all valid values for a UUID
	u[8] = (u[8] | 0x80) & 0xBF
	u[6] = (u[6] | 0x40) & 0x4F

	return hex.EncodeToString(u)
}

