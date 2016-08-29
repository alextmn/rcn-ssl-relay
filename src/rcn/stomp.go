package rcn

import (
	"bufio"
	"bytes"
	"errors"
	"net/url"
)

type Stomp struct {
	Cmd          string
	Body, Header map[string]string
}

func NewStomp(str [] byte) Stomp {
	p := Stomp{}
	stream := bufio.NewReader(bytes.NewReader(str))
	cmdBytes, _, _ := stream.ReadLine()
	p.Cmd = string(cmdBytes)
	toMap := func(stream *bufio.Reader, delim byte) (err error, m map[string]string) {
		m = make(map[string]string)
		for {
			line, _, err := stream.ReadLine()
			if (len(line) == 0) {
				break
			}
			if (err != nil) {
				return err, m
			}
			indx := bytes.IndexByte(line, delim)
			if (indx < 0) {
				return errors.New("unexpected stomp token " + string(line)), m
			}
			name := string(line[:indx])
			value := string(line[indx + 1:])
			m[name], _ = url.QueryUnescape(string(value))
		}
		return err, m
	}

	_, p.Header = toMap(stream, ':')
	//stream.ReadLine()
	_, p.Body = toMap(stream, '=')

	return p
}

func (m Stomp) ToStomp() ([]byte) {
	var buf bytes.Buffer
	buf.WriteString(m.Cmd)
	buf.WriteString("\n")
	f := func(a map[string]string, delim string) {
		if a != nil {
			for k, v := range a {
				buf.WriteString(k)
				buf.WriteString(delim)
				buf.WriteString(url.QueryEscape(v))
				buf.WriteString("\n")
			}
		}
	}
	f(m.Header, ":")
	buf.WriteString("\n")
	f(m.Body, "=")
	return buf.Bytes()
}


