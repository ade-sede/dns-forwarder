package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	A     uint16 = 1
	NS    uint16 = 2
	CNAME uint16 = 5
	SOA   uint16 = 6
	PTR   uint16 = 12
	MX    uint16 = 15
)

const (
	IN uint16 = 1
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

func (h *header) setQdCount(count uint16) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, count)

	copy(h.bytes[4:6], buf)
}

func (h *header) setAnCount(count uint16) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, count)

	copy(h.bytes[6:8], buf)
}

func encodeLabelSequence(s string) ([]byte, error) {
	buf := make([]byte, 0)

	labels := strings.Split(s, ".")

	for _, label := range labels {
		if len(label) > 63 {
			return buf, fmt.Errorf("Label %s is greated than the maximum allowed of 63", label)
		}

		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}

	buf = append(buf, byte(0))

	if len(buf) > 255 {
		return buf, fmt.Errorf("Domain name %s is greated than the maximum allowed of 255", s)
	}

	return buf, nil
}

func encodeIPV4Address(s string) ([]byte, error) {
	buf := make([]byte, 4)
	chunks := strings.Split(s, ".")

	for index, chunk := range chunks {
		chunkVal, err := strconv.ParseUint(chunk, 10, 8)
		if err != nil {
			return nil, err
		}

		buf[index] = byte(chunkVal)
	}

	return buf, nil
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

		query := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, query)

		response := make([]byte, 0)

		header := new(header)
		header.setId(1234)
		header.setQr(1)
		header.setQdCount(1)
		header.setAnCount(1)

		labelSequence, err := encodeLabelSequence("codecrafters.io")

		if err != nil {
			fmt.Println("Failed to encode domain name:", err)
		}

		ip, err := encodeIPV4Address("8.8.8.8")

		if err != nil {
			fmt.Println("Failed to encode ip address:", err)
		}

		// header
		response = append(response, header.bytes[0:12]...)

		// question
		response = append(response, labelSequence...)
		response = binary.BigEndian.AppendUint16(response, A)
		response = binary.BigEndian.AppendUint16(response, IN)

		// answer
		response = append(response, labelSequence...)
		response = binary.BigEndian.AppendUint16(response, A)
		response = binary.BigEndian.AppendUint16(response, IN)
		response = binary.BigEndian.AppendUint32(response, 60) // TTL
		response = binary.BigEndian.AppendUint16(response, 04) // LEN of data sent back
		response = append(response, ip...)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
