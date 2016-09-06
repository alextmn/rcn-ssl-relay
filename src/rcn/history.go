package rcn

import (
	"net"
	"time"
	"strconv"
)

func sendHistory(tr *StompTransport, cmd string, b map[string]string) {
	b["cmd"] = cmd
	s := Stomp{Cmd:"SEND",
		Header:map[string]string{"destination":HistQueue},
		Body:b}
	tr.Send(s)
}
func sendSs5ClosedHst(tr *StompTransport, compositeId string, diff int, start_time time.Time, endpoint net.Addr) {

	sendHistory(tr, "histSS5Closed", map[string]string{
		"compositeId":compositeId,
		"noMseconds":strconv.FormatInt(time.Since(start_time).Nanoseconds() / int64(time.Millisecond), 10),
		"start_time":strconv.FormatInt(start_time.Unix(), 10),
		"endpoint":endpoint.String(),
	})
}

func sendForwardClosedHst(tr *StompTransport, compositeId string, start_time  time.Time,
reason string, host string, port int, bytes_read int64, bytes_written int64, endpoint net.Addr) {
	sendHistory(tr, "histForwardClosed", map[string]string{
		"compositeId":compositeId,
		"noMseconds":strconv.FormatInt(time.Since(start_time).Nanoseconds() / int64(time.Millisecond), 10),
		"start_time":strconv.FormatInt(start_time.Unix(), 10),
		"endpoint":endpoint.String(),
	})

}