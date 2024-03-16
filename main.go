package main

import (
	"fmt"
	"log"
	"net/http"
)

//// Opening handshake
// GET /chat HTTP/1.1
// Host: server.example.com
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
// Origin: http://example.com
// Sec-WebSocket-Protocol: chat, superchat
// Sec-WebSocket-Version: 13

//// The handshake from the server looks as follows:
// HTTP/1.1 101 Switching Protocols
// Upgrade: websocket
// Connection: Upgrade
// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
// Sec-WebSocket-Protocol: chat

func websocketHandle(w http.ResponseWriter, r *http.Request) {
	ws, err := NewWebsocket(w, r)
	if err != nil {
		log.Println(err)
		return
	}

	if err = ws.Handshake(); err != nil {
		log.Println(err)
		return
	}

	defer ws.connection.Close()
}

func main() {
	http.HandleFunc("/", websocketHandle)

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
