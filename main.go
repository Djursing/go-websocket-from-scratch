package main

import (
	"fmt"
	"log"
	"net/http"
)

func websocketHandle(w http.ResponseWriter, r *http.Request) {
	ws, err := NewWebsocket(w, r)
	if err != nil {
		log.Println(err)
		return
	}

	if err = ws.handshake(); err != nil {
		log.Println(err)
		return
	}

	defer ws.connection.Close()

	for {
		frame, err := ws.recv()
		if err != nil {
			log.Println("Error decoding message", err)
			return
		}

		switch frame.Opcode {
		case 8: // Close
			return
		case 9: // Ping
			frame.Opcode = 10
			fallthrough
		case 0: // Continue
			fallthrough
		case 1: // Text
			fallthrough
		case 2: // Binary
			if err = ws.send(frame); err != nil {
				log.Println("Error sending message")
				return
			}
		}
	}

}

func main() {
	http.HandleFunc("/", websocketHandle)

	fmt.Printf("Starting server at port 9001\n")
	if err := http.ListenAndServe(":9001", nil); err != nil {
		log.Fatal(err)
	}
}
