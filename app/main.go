package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TYPES
const (
	A uint16 = 1
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
	question []*question
	answer   []*answer
}

func deserialize(frame []byte) (*message, error) {
	// HEADER
	header := new(header)
	copied := copy(header.bytes[:], frame)

	if copied < 12 {
		return nil, fmt.Errorf("invalid DNS header")
	}

	// QUESTION
	questions := make([]*question, 0, header.QDCOUNT())
	questionStart := 12

	for range header.QDCOUNT() {
		labelLen := bytes.IndexByte(frame[questionStart:], 0)

		if labelLen == -1 {
			return nil, fmt.Errorf("no label sequence found")
		}

		encodedLabelSequence := frame[questionStart : questionStart+labelLen+1]

		question := new(question)
		question.QNAME = encodedLabelSequence
		questions = append(questions, question)
	}

	message := message{
		header:   header,
		question: questions,
		answer:   nil,
	}

	return &message, nil
}

func createResponseMessage(initialMessage *message) (*message, error) {
	header := new(header)

	questions := make([]*question, 0, initialMessage.header.QDCOUNT())
	answers := make([]*answer, 0, initialMessage.header.QDCOUNT())

	copy(header.bytes[:], initialMessage.header.bytes[:])

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

	for i := range initialMessage.header.QDCOUNT() {
		question := new(question)
		answer := new(answer)

		question.QNAME = initialMessage.question[i].QNAME
		question.setType(A)
		question.setClass(IN)

		answer.NAME = initialMessage.question[i].QNAME
		answer.setType(A)
		answer.setClass(IN)
		answer.setTTL(30)
		err := answer.setIPV4data("8.8.8.8")
		if err != nil {
			return nil, err
		}

		questions = append(questions, question)
		answers = append(answers, answer)
	}

	header.setQDCOUNT(uint16(len(questions)))
	header.setANCOUNT(uint16(len(answers)))

	response := message{
		header:   header,
		question: questions,
		answer:   answers,
	}

	return &response, nil
}

func (m *message) serialize() []byte {
	totalLen := len(m.header.bytes) + m.questionLen() + m.answerLen()

	buf := make([]byte, 0, totalLen)

	buf = append(buf, m.header.bytes[:]...)

	for _, q := range m.question {
		buf = append(buf, q.QNAME...)
		buf = append(buf, q.QTYPE[:]...)
		buf = append(buf, q.QCLASS[:]...)
	}

	for _, a := range m.answer {
		buf = append(buf, a.NAME...)
		buf = append(buf, a.TYPE[:]...)
		buf = append(buf, a.CLASS[:]...)
		buf = append(buf, a.TTL[:]...)
		buf = append(buf, a.RDLENGTH[:]...)
		buf = append(buf, a.RDATA...)
	}

	return buf
}

func (m *message) questionLen() int {
	total := 0

	for _, q := range m.question {
		total += q.len()
	}

	return total
}

func (m *message) answerLen() int {
	total := 0

	for _, a := range m.answer {
		total += a.len()
	}

	return total
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

func (h *header) QDCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.bytes[4:6])
}

func (h *header) setANCOUNT(count uint16) {
	binary.BigEndian.PutUint16(h.bytes[6:8], count)
}

func (h *header) ANCOUNT() uint16 {
	return binary.BigEndian.Uint16(h.bytes[6:8])
}

func encodeLabelSequence(s string) ([]byte, error) {
	encodedLabelSequence := make([]byte, 0, len(s)+1)

	labels := strings.Split(s, ".")

	for _, label := range labels {
		if len(label) > 63 {
			return nil,
				fmt.Errorf("Max len of a label is 63.")
		}

		encodedLabelSequence = append(encodedLabelSequence, byte(len(label)))
		encodedLabelSequence = append(encodedLabelSequence, []byte(label)...)
	}

	encodedLabelSequence = append(encodedLabelSequence, byte(0))

	if len(encodedLabelSequence) > 255 {
		return nil, fmt.Errorf("Max len of a label seq is 255.")
	}

	return encodedLabelSequence, nil
}

type question struct {
	QNAME  []byte
	QTYPE  [2]byte
	QCLASS [2]byte
}

func (q *question) len() int {
	return len(q.QNAME) + 4
}

func (q *question) setType(t uint16) {
	binary.BigEndian.PutUint16(q.QTYPE[:], t)
}

func (q *question) setClass(c uint16) {
	binary.BigEndian.PutUint16(q.QCLASS[:], c)
}

type RR struct {
	NAME     []byte
	TYPE     [2]byte
	CLASS    [2]byte
	TTL      [4]byte
	RDLENGTH [2]byte
	RDATA    []byte
}

type answer = RR

func (rr *RR) len() int {
	return len(rr.NAME) + 10 + len(rr.RDATA)
}

func (rr *RR) setType(t uint16) {
	binary.BigEndian.PutUint16(rr.TYPE[:], t)
}

func (rr *RR) setClass(c uint16) {
	binary.BigEndian.PutUint16(rr.CLASS[:], c)
}

func (rr *RR) setTTL(ttl uint32) {
	binary.BigEndian.PutUint32(rr.TTL[:], ttl)
}

func (rr *RR) setIPV4data(ip string) error {
	buf := make([]byte, 4)
	chunks := strings.Split(ip, ".")

	for index, chunk := range chunks {
		chunkVal, err := strconv.ParseUint(chunk, 10, 8)
		if err != nil {
			return err
		}

		buf[index] = byte(chunkVal)
	}

	binary.BigEndian.PutUint16(rr.RDLENGTH[:], uint16(len(buf)))
	rr.RDATA = buf

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

		// Do not mutate the incoming frame
		incomingFrame := buf[:size]
		incomingMessage, err := deserialize(incomingFrame)
		if err != nil {
			fmt.Println("Error parsing the received frame:", err)
			continue
		}

		response, err := createResponseMessage(incomingMessage)
		if err != nil {
			fmt.Println("Error creating a response message:", err)
			continue
		}

		serialized := response.serialize()

		_, err = udpConn.WriteToUDP(*serialized, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
