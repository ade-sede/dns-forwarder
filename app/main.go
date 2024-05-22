package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
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
	QUERY uint8 = 0
	// RFC-1034 and RFC-1035 only specify 3 OPCODEs: 0 QUERY, 1 IQUERY, and 2 STATUS.
	// It reserves 3-15 for future use.
	// RFC-1996 specifies `NOTIFY` as OPCODE 4 but we're only implementing
	// a subset of RFC-1035 and use it for `UNIMPLEMENTED`.
	UNIMPLEMENTED uint8 = 4
)

// See QNAME & NAME definitions in RFC-1035 - 4.1.2 as well as 2.3.1
func encodeLabelSequence(labels []string) ([]byte, error) {
	encodedLabelSequence := make([]byte, 0)

	for _, label := range labels {
		if len(label) > 63 {
			return nil,
				fmt.Errorf("Max len of a label is 63.")
		}

		// Note: we never compress the labels
		// The chosen solution of high level representation makes it
		// hard to do proper compression and it is not required by our
		// test suite.
		encodedLabelSequence = append(encodedLabelSequence, byte(len(label)))
		encodedLabelSequence = append(encodedLabelSequence, []byte(label)...)
	}

	encodedLabelSequence = append(encodedLabelSequence, byte(0))

	if len(encodedLabelSequence) > 255 {
		return nil, fmt.Errorf("Max len of a label seq is 255.")
	}

	return encodedLabelSequence, nil
}

func extractBytes(src []byte, offset *int, length int) []byte {
	result := src[*offset : *offset+length]
	*offset += length
	return result
}

func extractUint16(src []byte, offset *int) ([2]byte, uint16) {
	result := [2]byte{src[*offset], src[*offset+1]}
	*offset += 2
	return result, binary.BigEndian.Uint16(result[:])
}

func extractUint32(src []byte, offset *int) ([4]byte, uint32) {
	result := [4]byte{src[*offset], src[*offset+1], src[*offset+2], src[*offset+3]}
	*offset += 4
	return result, binary.BigEndian.Uint32(result[:])
}

// RFC-1035 - 4.1 - Message Format
type message struct {
	cache *labelCache

	// SECTIONS
	header   *header
	question []*question
	answer   []*answer
	// unusupported by this server
	authority []*RR
	// unusupported by this server
	additional []*RR
}

// RFC-1035 4.1.4. Message compression
// The architecture I have chosen makes it hard to implement compression properly.
// Normally, it is a simple pointer to a previous label in the frame.
// Paying the price for my early design decisions... Never abstract too early.
// There are two major drawbacks:
// 1. We cannot easily compress messages
// 2. We cannot follow recursive pointers (rare as they may be)
type labelCache struct {
	// Map label to position
	labelMap map[string]int
	// Position to label
	positionMap map[int]string
}

// When we have a reference to a previous label, we need to
// include the label we encountered and each subsequent label
// For example, consider the following situation
// - `google` label starts at byte 12
// - `com` label starts at byte 19
// If later we encounter a reference to `google.com` at byte 12
// we need to include `google` and `com` in the label sequence.
func (c *labelCache) allSubsequentLabels(head int) []string {
	labels := make([]string, 0)

	for {
		if label, ok := c.positionMap[head]; ok {
			labels = append(labels, label)
			head += len(label) + 1
			continue
		}

		break
	}

	return labels
}

func decodeLabels(frame []byte, head *int, cache *labelCache) ([]string, error) {
	labels := make([]string, 0)

	for {
		if frame[*head] == 0 {
			*head++
			break
		}

		if frame[*head] == 192 {
			pointer := int(frame[*head+1])

			referencedLabels := cache.allSubsequentLabels(pointer)

			if len(referencedLabels) == 0 {
				return labels, fmt.Errorf("Invalid label reference: %d", frame[*head+1])
			}

			labels = append(labels, referencedLabels...)

			*head += 2
			break
		}

		labelLen := int(frame[*head])
		labelPosition := *head
		*head += 1

		label := string(extractBytes(frame, head, labelLen))

		cache.labelMap[label] = labelPosition
		cache.positionMap[labelPosition] = label
		labels = append(labels, label)
	}

	return labels, nil
}

func deserialize(frame []byte) (*message, error) {
	cache := labelCache{
		labelMap:    make(map[string]int),
		positionMap: make(map[int]string),
	}

	// HEADER
	header := new(header)
	copied := copy(header.bytes[:], frame)

	if copied < 12 {
		return nil, fmt.Errorf("invalid DNS header")
	}

	// QUESTION
	questions := make([]*question, 0, header.QDCOUNT())
	head := 12

	for i := uint16(0); i < header.QDCOUNT(); i++ {
		question := new(question)

		labels, err := decodeLabels(frame, &head, &cache)

		if err != nil {
			return nil, err
		}

		question.QNAME = labels
		question.QTYPE, _ = extractUint16(frame, &head)
		question.QCLASS, _ = extractUint16(frame, &head)
		questions = append(questions, question)
	}

	// ANSWER
	answers := make([]*answer, 0, header.ANCOUNT())

	for i := uint16(0); i < header.ANCOUNT(); i++ {
		answer := new(answer)

		labels, err := decodeLabels(frame, &head, &cache)

		if err != nil {
			return nil, err
		}

		var rdLength uint16

		answer.NAME = labels
		answer.TYPE, _ = extractUint16(frame, &head)
		answer.CLASS, _ = extractUint16(frame, &head)
		answer.TTL, _ = extractUint32(frame, &head)
		answer.RDLENGTH, rdLength = extractUint16(frame, &head)
		answer.RDATA = extractBytes(frame, &head, int(rdLength))

		answers = append(answers, answer)
	}

	message := message{
		cache:    &cache,
		header:   header,
		question: questions,
		answer:   answers,
	}

	return &message, nil
}

func createResponseMessage(initialMessage *message) *message {
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

	for i := uint16(0); i < initialMessage.header.QDCOUNT(); i++ {
		question := new(question)

		question.QNAME = initialMessage.question[i].QNAME
		question.setType(A)
		question.setClass(IN)

		questions = append(questions, question)
	}

	header.setQDCOUNT(uint16(len(questions)))

	response := message{
		header:   header,
		question: questions,
		answer:   answers,
	}

	return &response
}

func forwardResolve(questions []*question, conn *net.UDPConn) ([]*answer, error) {
	// The motivation behind forwarding each question in its own query is
	// unclear to me, but it is what the test suite from codecrafters expects
	// and therefore it's what I'll do

	answers := make([]*answer, 0, len(questions))

	for _, q := range questions {
		message := message{
			header:   new(header),
			question: []*question{q},
			answer:   nil,
		}

		message.header.setId(uint16(rand.IntN(math.MaxUint16)))
		message.header.setQR(0)
		message.header.setAA(0)
		message.header.setTC(0)
		message.header.setRA(0)
		message.header.setRD(1)
		message.header.setZ(0)
		message.header.setQDCOUNT(1)

		serialized, err := message.serialize()
		if err != nil {
			return answers, err
		}

		_, err = conn.Write(serialized)
		if err != nil {
			return answers, fmt.Errorf("Failed to send query to resolver")
		}

		buf := make([]byte, 512)
		size, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return answers, fmt.Errorf("Failed to read response from resolver")
		}

		incomingFrame := buf[:size]
		resolverResponse, err := deserialize(incomingFrame)
		if err != nil {
			return answers, fmt.Errorf("Failed to parse response from resolver")
		}

		answers = append(answers, resolverResponse.answer...)
	}

	return answers, nil
}

func (m *message) addStaticAnswer() error {
	// This server is a toy project.
	// It does not actually store any records.
	// When it is *not* in forwarder mode it answers every request with the
	// same IP address and same TTL.
	ip, err := netip.ParseAddr("8.8.8.8")
	if err != nil {
		return fmt.Errorf("Failed to parse IP address")
	}

	for i := uint16(0); i < m.header.QDCOUNT(); i++ {
		answer := new(answer)

		answer.NAME = m.question[i].QNAME
		answer.setType(A)
		answer.setClass(IN)
		answer.setTTL(60)
		answer.setData(ip.AsSlice())

		m.answer = append(m.answer, answer)
	}

	m.header.setANCOUNT(uint16(len(m.answer)))

	return nil
}

func (m *message) serialize() ([]byte, error) {
	totalLen := len(m.header.bytes) + m.questionLen() + m.answerLen()

	buf := make([]byte, 0, totalLen)

	buf = append(buf, m.header.bytes[:]...)

	for _, q := range m.question {
		encodedLabelSequence, err := encodeLabelSequence(q.QNAME)
		if err != nil {
			return buf, err
		}

		buf = append(buf, encodedLabelSequence...)
		buf = append(buf, q.QTYPE[:]...)
		buf = append(buf, q.QCLASS[:]...)
	}

	for _, a := range m.answer {
		encodedLabelSequence, err := encodeLabelSequence(a.NAME)
		if err != nil {
			return buf, err
		}

		buf = append(buf, encodedLabelSequence...)
		buf = append(buf, a.TYPE[:]...)
		buf = append(buf, a.CLASS[:]...)
		buf = append(buf, a.TTL[:]...)
		buf = append(buf, a.RDLENGTH[:]...)
		buf = append(buf, a.RDATA...)
	}

	return buf, nil
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

// RFC 1035 - 4.1.1 - Header section format
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

// RFC 1035 - 4.1.2 - Question section format
type question struct {
	QNAME  []string
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

// RFC 1035 - 4.1.3 - RR format
type RR struct {
	NAME     []string
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

func (rr *RR) setData(data []byte) {
	binary.BigEndian.PutUint16(rr.RDLENGTH[:], uint16(len(data)))
	rr.RDATA = data
}

func parseResolverAddress(addr string) (string, error) {
	ip, port, err := net.SplitHostPort(addr)

	if err != nil {
		if addrErr, ok := err.(*net.AddrError); ok && addrErr.Err == "missing port in address" {
			ip = addr
			port = "53"
		}

	}

	parsedIp := net.ParseIP(ip)

	if parsedIp.To4() == nil || parsedIp.To16() == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid port number: %s", port)
	}

	return fmt.Sprintf("%s:%s", ip, port), nil
}

func main() {
	var resolverConn *net.UDPConn

	if len(os.Args) == 3 && os.Args[1] == "--resolver" {
		addr, err := parseResolverAddress(os.Args[2])
		if err != nil {
			fmt.Println("Failed to parse resolver address:", err)
			return
		}

		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			fmt.Println("Failed to resolve UDP address:", err)
			return
		}

		resolverConn, err = net.DialUDP("udp", nil, uaddr)
		if err != nil {
			fmt.Println("Failed to connect to resolver:", err)
			return
		}
		defer resolverConn.Close()
	}

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

		response := createResponseMessage(incomingMessage)

		if resolverConn != nil {
			answers, err := forwardResolve(response.question, resolverConn)

			if err != nil {
				fmt.Println("Error forwarding the request:", err)
				continue
			}

			response.answer = answers
			response.header.setANCOUNT(uint16(len(answers)))
		} else {
			err = response.addStaticAnswer()
			if err != nil {
				fmt.Println("Error while creating answer:", err)
				continue
			}
		}

		serialized, err := response.serialize()
		if err != nil {
			fmt.Println("Error serializing the message:", err)
			continue
		}

		_, err = udpConn.WriteToUDP(serialized, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
			continue
		}

	}
}
