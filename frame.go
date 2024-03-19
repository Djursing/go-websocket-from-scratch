package main

import (
	"bytes"
	"encoding/binary"
)

type Frame struct {
	IsFragment bool
	RSV        byte
	Opcode     byte
	IsMasked   bool
	Length     byte
	Payload    []byte
}

// Get the Pong frame
func (frame Frame) Pong() Frame {
	frame.Opcode = 10
	return frame
}

// Get Text Payload
func (frame Frame) Text() string {
	return string(frame.Payload)
}

// IsControl checks if the frame is a control frame identified by opcodes where the most significant bit of the opcode is 1
func (frame *Frame) IsControl() bool {
	return frame.Opcode&0x08 == 0x08
}

func (frame *Frame) HasReservedOpcode() bool {
	return frame.Opcode > 10 || (frame.Opcode >= 3 && frame.Opcode <= 7)
}

func (frame *Frame) CloseCode() uint16 {
	var code uint16
	binary.Read(bytes.NewReader(frame.Payload), binary.BigEndian, &code)
	return code
}
