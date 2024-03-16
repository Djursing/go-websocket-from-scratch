package main

type Frame struct {
	IsFragment bool
	RSV        byte
	Opcode     byte
	IsMasked   bool
	Length     byte
	Payload    []byte
}
