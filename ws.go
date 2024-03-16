package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
)

const bufferSize = 4096

type Connection interface {
	Close() error
}

var closeCodes map[int]string = map[int]string{
	1000: "NormalError",
	1001: "GoingAwayError",
	1002: "ProtocolError",
	1003: "UnknownType",
	1007: "TypeError",
	1008: "PolicyError",
	1009: "MessageTooLargeError",
	1010: "ExtensionError",
	1011: "UnexpectedError",
}

// Generate acceptHash for "Sec-WebSocket-Key" header
func getAcceptHash(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("58EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type Websocket struct {
	connection Connection
	bufrw      *bufio.ReadWriter
	header     http.Header
	status     uint16
}

// Hijacks the https request and returns a new websocket
func NewWebsocket(w http.ResponseWriter, r *http.Request) (*Websocket, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("webserver doesn't support hijackin")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	return &Websocket{conn, bufrw, r.Header, 1000}, nil
}

// Reads a given amount of bytes from the websocket
func (ws *Websocket) read(bytesToRead int) ([]byte, error) {
	data := make([]byte, 0)

	for {
		// Break if all data has been read
		if len(data) == bytesToRead {
			break
		}

		chunk := bufferSize
		remaining := bytesToRead - len(data)

		// Make sure we don't read beyond
		if chunk > remaining {
			chunk = remaining
		}

		tmp := make([]byte, chunk)

		n, err := ws.bufrw.Read(tmp)
		if err != nil && err != io.EOF {
			return data, err
		}

		data = append(data, tmp[:n]...)
	}

	return data, nil
}

func (ws *Websocket) write(data []byte) error {
	_, err := ws.bufrw.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// Perform websocket handshake
func (ws *Websocket) Handshake() error {
	hash := getAcceptHash(ws.header.Get("Sec-WebSocket-Key"))
	headers := []string{
		"HTTP/1.1 101 Web Socket Protocol Handshake",
		"Server: go/testserver",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + hash,
	}
	// "", // required for extra CRLF
	// 	"", // required for extra CRLF

	return ws.write([]byte(strings.Join(headers, "\r\n")))
}

func (ws *Websocket) Recv() (Frame, error) {
	frame := Frame{}
	head, err := ws.read(2)
	if err != nil {
		return frame, err
	}

	// First bit in first byte
	frame.IsFragment = (head[0] & 0x80) == 0x00

	// Bits 2-4
	frame.RSV = head[0] & 0x70

	// Bits 4-7
	frame.Opcode = head[0] & 0x0F

	// First bit in second byte
	frame.IsMasked = (head[1] & 0x80) == 0x80

	// The payload length can extend up to 127 bits
	// the first bit is allocated to the MASK
	var payloadLength uint64
	payloadLength = uint64(head[1] & 0x7F)

	// Data is in the next 2 bytes
	if payloadLength == 126 {
		data, err := ws.read(2)
		if err != nil {
			return frame, err
		}

		payloadLength = uint64(binary.BigEndian.Uint16(data))

		// Data is in the next 8 bytes
	} else if payloadLength == 127 {
		data, err := ws.read(8)
		if err != nil {
			return frame, err
		}

		payloadLength = uint64(binary.BigEndian.Uint16(data))
	}

	// Get masked keys used for decoding payload
	mask, err := ws.read(4)
	if err != nil {
		return frame, err
	}

	frame.Length = byte(payloadLength)

	payload, err := ws.read(int(payloadLength)) // Possible data loss when converting from uint64 to int
	if err != nil {
		return frame, err
	}

	// Decode each byte of the payload
	for i := uint64(0); i < payloadLength; i++ {
		payload[i] ^= mask[i%4]
	}

	frame.Payload = payload

	return frame, nil
}
