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

type query struct {
	header   *header
	question *question
	answer   *answer
}

func (q *query) pack() *[]byte {
	totalLen := len(q.header.bytes) + q.question.len() + q.answer.len()

	buf := make([]byte, 0, totalLen)

	buf = append(buf, q.header.bytes[:]...)
	buf = append(buf, *q.question.encodedLabelSequence...)
	buf = append(buf, q.question.recordType[:]...)
	buf = append(buf, q.question.recordClass[:]...)
	buf = append(buf, *q.answer.encodedLabelSequence...)
	buf = append(buf, q.answer.recordType[:]...)
	buf = append(buf, q.answer.recordClass[:]...)
	buf = append(buf, q.answer.ttl[:]...)
	buf = append(buf, q.answer.rdlength[:]...)
	buf = append(buf, *q.answer.rdata...)

	return &buf
}

type header struct {
	bytes [12]byte
}

func (h *header) setId(id uint16) {
	binary.BigEndian.PutUint16(h.bytes[0:2], id)
}

func (h *header) setQr(isReply uint8) {
	h.bytes[2] = h.bytes[2] | isReply<<7
}

func (h *header) setQdCount(count uint16) {
	binary.BigEndian.PutUint16(h.bytes[4:6], count)
}

func (h *header) setAnCount(count uint16) {
	binary.BigEndian.PutUint16(h.bytes[6:8], count)
}

func encodeLabelSequence(s string) (*[]byte, error) {
	encodedLabelSequence := make([]byte, 0, len(s)+1)

	labels := strings.Split(s, ".")

	for _, label := range labels {
		if len(label) > 63 {
			return nil,
				fmt.Errorf("Max len of a label is 63. %s is %d", label, len(label))
		}

		encodedLabelSequence = append(encodedLabelSequence, byte(len(label)))
		encodedLabelSequence = append(encodedLabelSequence, []byte(label)...)
	}

	encodedLabelSequence = append(encodedLabelSequence, byte(0))

	if len(encodedLabelSequence) > 255 {
		return nil, fmt.Errorf("Max len of a label seq is 255. %s is %d", s, len(s))
	}

	return &encodedLabelSequence, nil
}

type question struct {
	encodedLabelSequence *[]byte
	recordType           [2]byte
	recordClass          [2]byte
}

func (q *question) len() int {
	return len(*q.encodedLabelSequence) + 4
}

func (q *question) setType(t uint16) {
	binary.BigEndian.PutUint16(q.recordType[:], t)
}

func (q *question) setClass(c uint16) {
	binary.BigEndian.PutUint16(q.recordClass[:], c)
}

type answer struct {
	encodedLabelSequence *[]byte
	recordType           [2]byte
	recordClass          [2]byte
	ttl                  [4]byte
	rdlength             [2]byte
	rdata                *[]byte
}

func (a *answer) len() int {
	return len(*a.encodedLabelSequence) + 10 + len(*a.rdata)
}

func (a *answer) setType(t uint16) {
	binary.BigEndian.PutUint16(a.recordType[:], t)
}

func (a *answer) setClass(c uint16) {
	binary.BigEndian.PutUint16(a.recordClass[:], c)
}

func (a *answer) setTTL(ttl uint32) {
	binary.BigEndian.PutUint32(a.ttl[:], ttl)
}

func (a *answer) setIPV4data(ip string) error {
	buf := make([]byte, 4)
	chunks := strings.Split(ip, ".")

	for index, chunk := range chunks {
		chunkVal, err := strconv.ParseUint(chunk, 10, 8)
		if err != nil {
			return err
		}

		buf[index] = byte(chunkVal)
	}

	binary.BigEndian.PutUint16(a.rdlength[:], uint16(len(buf)))
	a.rdata = &buf

	return nil

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

		incoming := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, incoming)

		header := new(header)
		question := new(question)
		answer := new(answer)

		response := query{
			header:   header,
			question: question,
			answer:   answer,
		}

		header.setId(1234)
		header.setQr(1)
		header.setAnCount(1)
		header.setQdCount(1)

		labelSequence, err := encodeLabelSequence("codecrafters.io")
		if err != nil {
			fmt.Println("Failed to encode label sequence:", err)
		}

		question.encodedLabelSequence = labelSequence
		question.setType(A)
		question.setClass(IN)

		answer.encodedLabelSequence = labelSequence
		answer.setType(A)
		answer.setClass(IN)
		answer.setTTL(30)
		err = answer.setIPV4data("8.8.8.8")
		if err != nil {
			fmt.Println("Failed to encode IPV4 address as rdata:", err)
		}

		packed := response.pack()

		_, err = udpConn.WriteToUDP(*packed, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
