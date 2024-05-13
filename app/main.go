package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type header struct {
	bytes [12]byte
}

func (h *header) setId(id uint16) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, id)

	copy(h.bytes[0:2], buf)
}

func (h *header) setQr(isReply uint8) {
	h.bytes[2] = h.bytes[2] | isReply<<7
}

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		header := new(header)
		header.setId(1234)
		header.setQr(1)

		response := make([]byte, 512)

		copy(response, header.bytes[0:12])

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
