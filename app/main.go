package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TYPES
const (
	A     uint16 = 1
	NS    uint16 = 2
	CNAME uint16 = 5
	SOA   uint16 = 6
	PTR   uint16 = 12
	MX    uint16 = 15
)

// CLASSES
const (
	IN uint16 = 1
)

// OPCODES
const (
	QUERY         uint8 = 0
	IQUERY        uint8 = 1
	STATUS        uint8 = 2
	UNIMPLEMENTED uint8 = 4
)

type message struct {
	header   *header
	question *question
	answer   *answer
}

func parse(frame *[]byte) (*message, error) {
	header := new(header)

	if len(*frame) < 12 {
		return nil, fmt.Errorf("no header")
	}

	copy(header.bytes[:], *frame)

	message := message{
		header:   header,
		question: nil,
		answer:   nil,
	}

	return &message, nil
}

func createResponseMessage(initialMessage *message) (*message, error) {
	header := new(header)
	question := new(question)
	answer := new(answer)

	copy(header.bytes[:], initialMessage.header.bytes[:])

	response := message{
		header:   header,
		question: question,
		answer:   answer,
	}

	header.setQR(1)
	header.setAA(0)
	header.setTC(0)
	header.setRA(0)
	header.setZ(0)

	if initialMessage.header.OPCODE() == QUERY {
		header.setRCODE(QUERY)
	} else {
		header.setRCODE(UNIMPLEMENTED)
	}

	labelSequence, err := encodeLabelSequence("codecrafters.io")
	if err != nil {
		return nil, err
	}

	question.encodedLabelSequence = labelSequence
	question.setType(A)
	question.setClass(IN)
	header.setQDCOUNT(1)

	answer.encodedLabelSequence = labelSequence
	answer.setType(A)
	answer.setClass(IN)
	answer.setTTL(30)
	err = answer.setIPV4data("8.8.8.8")
	if err != nil {
		return nil, err
	}
	header.setANCOUNT(1)

	return &response, nil
}

func (q *message) pack() *[]byte {
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

func (h *header) id() uint16 {
	return binary.BigEndian.Uint16(h.bytes[0:2])
}

func (h *header) setQR(isReply uint8) {
	h.bytes[2] = h.bytes[2] | isReply<<7
}

func (h *header) OPCODE() uint8 {
	return (h.bytes[2] & 0b01111000) >> 3
}

func (h *header) setAA(isAuthoritativeAnswer uint8) {
	h.bytes[2] = h.bytes[2] | isAuthoritativeAnswer<<2
}

func (h *header) setTC(isTruncated uint8) {
	h.bytes[2] = h.bytes[2] | isTruncated<<1
}

func (h *header) setRD(recursionDesired uint8) {
	h.bytes[2] = h.bytes[2] | recursionDesired
}

func (h *header) RD() uint8 {
	return h.bytes[2] & 0b00000001
}

func (h *header) setRA(recursionAvailable uint8) {
	h.bytes[3] = h.bytes[3] | recursionAvailable<<7
}

func (h *header) setZ(val uint8) {
	h.bytes[3] = (h.bytes[3] & 0b10001111) | (val & 0b01110000)
}

func (h *header) setRCODE(code uint8) {
	h.bytes[3] = (h.bytes[3] & 0b11110000) | (code & 0b00001111)
}

func (h *header) setQDCOUNT(count uint16) {
	binary.BigEndian.PutUint16(h.bytes[4:6], count)
}

func (h *header) setANCOUNT(count uint16) {
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

		incomingFrame := buf[:size]
		incomingMessage, err := parse(&incomingFrame)
		if err != nil {
			fmt.Println("Error parsing the received frame:", err)
			continue
		}

		response, err := createResponseMessage(incomingMessage)
		if err != nil {
			fmt.Println("Error creating a response message:", err)
			continue
		}

		packed := response.pack()

		_, err = udpConn.WriteToUDP(*packed, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
