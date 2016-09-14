package rcn

import (
	"net"
	"time"
	"strconv"
	"strings"
)

func sendHistory(tr *StompTransport, cmd string, b map[string]string) {
	b["cmd"] = cmd
	s := Stomp{Cmd:"SEND",
		Header:map[string]string{"destination":HistQueue},
		Body:b}
	tr.Send(s)
}
func sendSs5ClosedHst(tr *StompTransport, compositeId string, startedTime time.Time, endpoint net.Addr) {

	sendHistory(tr, "histSS5Closed", map[string]string{
		"compositeId":compositeId,
		"noMseconds":strconv.FormatInt(time.Since(startedTime).Nanoseconds() / int64(time.Millisecond), 10),
		"startTime":strconv.FormatInt(startedTime.Unix(), 10),
		"endpoint":endpoint.String(),
	})
}

func sendForwardStartHst(tr *StompTransport, compositeId string, address string, endpoint net.Addr) {
	sendHistory(tr, "histForwardStarted", map[string]string{
		"compositeId":compositeId,
		"address":address,
		"startTime":strconv.FormatInt(time.Now().Unix(), 10),
		"endpoint":endpoint.String(),
	})
}

func sendForwardClosedHst(tr *StompTransport, compositeId string, started  time.Time,
address string, bytesRead, bytesWritten int64, endpoint net.Addr) {
	sendHistory(tr, "histForwardClosed", map[string]string{
		"compositeId":compositeId,
		"startTime":strconv.FormatInt(time.Now().Unix(), 10),
		"noMseconds":strconv.FormatInt(time.Since(started).Nanoseconds() / int64(time.Millisecond), 10),
		"bytesRead":strconv.FormatInt(bytesRead, 10),
		"bytesWritten":strconv.FormatInt(bytesWritten, 10),
		"address":address,
		"endpoint":endpoint.String(),
	})
}

func sendRelayStartHst(tr *StompTransport, idBind, idConnect string,
address1, address2  net.Addr, isBindSsl, isConnectSsl bool) {
	a1 := strings.Split(address1.String(), ":")
	a2 := strings.Split(address2.String(), ":")

	sendHistory(tr, "histRelayStarted", map[string]string{
		"idBind":idBind,
		"idConnect":idConnect,
		"startTime":strconv.FormatInt(time.Now().Unix(), 10),
		"address1":a1[0],
		"address2":a2[0],
		"p1":a1[1],
		"p2":a2[1],
		"isBindSsl":strconv.FormatBool(isBindSsl),
		"isConnect":strconv.FormatBool(isConnectSsl),
	})
}

func sendRelayCloseHst(tr *StompTransport, idBind, idConnect string,
address1, address2  net.Addr, isBindSsl, isConnectSsl bool,
bytesRead, bytesWritten int64, startedTime time.Time) {
	a1 := strings.Split(address1.String(), ":")
	a2 := strings.Split(address2.String(), ":")

	sendHistory(tr, "histRelayClose", map[string]string{
		"idBind":idBind,
		"idConnect":idConnect,
		"address1":a1[0],
		"address2":a2[0],
		"p1":a1[1],
		"p2":a2[1],
		"startTime":strconv.FormatInt(time.Now().Unix(), 10),
		"isBindSsl":strconv.FormatBool(isBindSsl),
		"isConnect":strconv.FormatBool(isConnectSsl),
		"noMseconds":strconv.FormatInt(time.Since(startedTime).Nanoseconds() / int64(time.Millisecond), 10),
		"bytesRead":strconv.FormatInt(bytesRead, 10),
		"bytesWritten":strconv.FormatInt(bytesWritten,10),
	})

}