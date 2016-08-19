package rcn

import (
	"strconv"
	"log"
	"encoding/binary"
	"net"
	"io"
	"bytes"
	"errors"
	"fmt"
)

func ss5(con net.Conn, revoked error) (err error) {
	remote := con.RemoteAddr()
	var buf []byte

	read := func(size int, eStr string) (err error) {
		buf = make([]byte, size)
		if _, err = io.ReadFull(con, buf); err != nil {
			log.Printf(eStr + ". %v %v", err, remote)
		}
		return
	}

	write := func(b []byte, eStr string) (err error) {
		if _, err = io.Copy(con, bytes.NewReader(b)); err != nil {
			log.Printf(eStr + ". %v", err)

		}
		return
	}

	//step 1
	if err = read(2, "ss5 st1 error"); err != nil {
		return
	}

	if buf[0] != 0x5 {
		err = errors.New(fmt.Sprintf("protocol error %v", remote))
		return
	}

	nbAuth := buf[1];

	if nbAuth < 1 {
		nbAuth = 1
	}

	//step 2
	if err = read(int(nbAuth), "ss5 st1 auth methods error"); err != nil {
		return
	}
	authType := buf[0]
	if err = write([]byte{0x5, authType}, "ss5 st1 write error"); err != nil {
		return
	}

	//step 3
	if err = read(4, "ss5 st2 select auth error"); err != nil {
		return
	}

	if authType == 0x1e {
		certLen := int(binary.BigEndian.Uint32(buf))

		log.Printf("0x1e cert len: %v", certLen)
		if certLen < 0 || certLen > 32000 {
			err = errors.New(fmt.Sprintf("0x1E cert incorrect size:%v", certLen))
			return
		}
		if err = read(certLen, "ss5 cert"); err != nil {
			return
		}
		log.Printf("0x1e cert:\n %v", string(buf))

		// TODO:cert check //////////////////////////

		if err = read(4, "0x1e cert st3"); err != nil {
			return
		}

	}
	//check version
	if buf[0] != 0x5 {
		err = errors.New(fmt.Sprintf("ss5 st3 protocal error. value=%v", buf[0]))
		return err
	}
	typeOp := buf[1]
	typeAddr := buf[3]

	log.Printf("ss5 typeOp:%v typeAddr:%v %v", typeOp, typeAddr, remote)

	bouceHost := ""
	port := 0
	//
	switch typeAddr {
	case 3:
		if err = read(1, "domain len error"); err != nil {
			return
		}
		//domain
		if err = read(int(buf[0]), "domain error"); err != nil {
			return
		}
		bouceHost = string(buf)
	case 1:
		if err = read(4, "ss5 ip4 len error"); err != nil {
			return
		}
		bouceHost = strconv.Itoa(int(buf[0])) + "." + strconv.Itoa(int(buf[1])) +
			"." + strconv.Itoa(int(buf[2])) + "." + strconv.Itoa(int(buf[3]))

	default:
		err = errors.New(fmt.Sprintf("ss5 type operation is not supported. value=%v", typeOp))
		return
	}

	if err = read(2, "ss5 port error"); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(buf))

	if (revoked != nil) {
		write([]byte("REVOKED"), "")
		err = errors.New(fmt.Sprintf("REVOKED. %v %v", revoked, remote))
		return
	}

	if err = write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "ss5 final write failed"); err != nil {
		return
	}


	log.Printf("finished: %v:%v", bouceHost, port)

	return
}



