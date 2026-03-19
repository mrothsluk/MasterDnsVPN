// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"encoding/binary"

	Enums "masterdnsvpn-go/internal/enums"
)

const (
	maxLikelyQuestions  = 64
	maxLikelyAnswers    = 256
	maxLikelyAuthority  = 256
	maxLikelyAdditional = 256
)

func BuildEmptyNoErrorResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_NO_ERROR)
}

func BuildEmptyNoErrorResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NO_ERROR)
}

func BuildFormatErrorResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_FORMAT_ERROR)
}

func BuildFormatErrorResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_FORMAT_ERROR)
}

func BuildRefusedResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_REFUSED)
}

func BuildServerFailureResponse(request []byte) ([]byte, error) {
	return buildResponseWithRCode(request, Enums.DNSR_CODE_SERVER_FAILURE)
}

func BuildServerFailureResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_SERVER_FAILURE)
}

func BuildNotImplementedResponseFromLite(request []byte, parsed LitePacket) ([]byte, error) {
	return buildResponseWithRCodeLite(request, parsed, Enums.DNSR_CODE_NOT_IMPLEMENTED)
}

func buildResponseWithRCode(request []byte, rcode uint8) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(request)
	if !isLikelyDNSRequestHeader(header) {
		return nil, ErrNotDNSRequest
	}

	questionBytes, questionCount := extractQuestionSection(request, header)
	optRecords := extractOPTRecordsFromRequest(request, header, len(questionBytes) > 0 || header.QDCount == 0)

	response := make([]byte, dnsHeaderSize+len(questionBytes)+rawRecordsLen(optRecords))
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, rcode))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(len(optRecords)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	for _, record := range optRecords {
		offset += copy(response[offset:], record)
	}

	return response, nil
}

func buildResponseWithRCodeLite(request []byte, parsed LitePacket, rcode uint8) ([]byte, error) {
	if len(request) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}
	if !isLikelyDNSRequestHeader(parsed.Header) {
		return nil, ErrNotDNSRequest
	}

	questionBytes := []byte(nil)
	questionCount := uint16(0)
	if parsed.QuestionEndOffset >= dnsHeaderSize && parsed.QuestionEndOffset <= len(request) {
		questionBytes = request[dnsHeaderSize:parsed.QuestionEndOffset]
		questionCount = parsed.Header.QDCount
	}

	optRecords := extractOPTRecordsFromOffset(request, parsed.Header, parsed.QuestionEndOffset)

	response := make([]byte, dnsHeaderSize+len(questionBytes)+rawRecordsLen(optRecords))
	binary.BigEndian.PutUint16(response[0:2], parsed.Header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(parsed.Header.Flags, rcode))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(len(optRecords)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	for _, record := range optRecords {
		offset += copy(response[offset:], record)
	}

	return response, nil
}

func isLikelyDNSRequestHeader(header Header) bool {
	if header.QR != 0 {
		return false
	}
	if header.OpCode > 6 {
		return false
	}
	if header.QDCount > maxLikelyQuestions {
		return false
	}
	if header.ANCount > maxLikelyAnswers {
		return false
	}
	if header.NSCount > maxLikelyAuthority {
		return false
	}
	if header.ARCount > maxLikelyAdditional {
		return false
	}
	return true
}

func buildResponseFlags(requestFlags uint16, rcode uint8) uint16 {
	var responseFlags uint16

	responseFlags |= 1 << 15
	responseFlags |= requestFlags & 0x7800
	responseFlags |= requestFlags & (1 << 8)
	responseFlags |= requestFlags & (1 << 4)
	responseFlags |= uint16(rcode & 0x0F)

	return responseFlags
}

func extractQuestionSection(request []byte, header Header) ([]byte, uint16) {
	if header.QDCount == 0 {
		return nil, 0
	}

	offset, err := skipQuestions(request, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return nil, 0
	}

	return request[dnsHeaderSize:offset], header.QDCount
}

func extractOPTRecordsFromRequest(request []byte, header Header, canWalk bool) [][]byte {
	if !canWalk || header.ARCount == 0 {
		return nil
	}

	offset, err := skipQuestions(request, dnsHeaderSize, int(header.QDCount))
	if err != nil {
		return nil
	}

	offset, err = skipResourceRecords(request, offset, int(header.ANCount))
	if err != nil {
		return nil
	}

	offset, err = skipResourceRecords(request, offset, int(header.NSCount))
	if err != nil {
		return nil
	}

	records, _, err := extractRawOPTRecords(request, offset, int(header.ARCount))
	if err != nil {
		return nil
	}

	return records
}

func extractOPTRecordsFromOffset(request []byte, header Header, questionEndOffset int) [][]byte {
	if header.ARCount == 0 {
		return nil
	}
	if questionEndOffset < dnsHeaderSize || questionEndOffset > len(request) {
		return nil
	}

	offset := questionEndOffset
	var err error
	offset, err = skipResourceRecords(request, offset, int(header.ANCount))
	if err != nil {
		return nil
	}

	offset, err = skipResourceRecords(request, offset, int(header.NSCount))
	if err != nil {
		return nil
	}

	records, _, err := extractRawOPTRecords(request, offset, int(header.ARCount))
	if err != nil {
		return nil
	}

	return records
}

func rawRecordsLen(records [][]byte) int {
	total := 0
	for _, record := range records {
		total += len(record)
	}
	return total
}

func skipQuestions(data []byte, offset int, count int) (int, error) {
	for range count {
		nextOffset, err := skipName(data, offset)
		if err != nil {
			return offset, ErrInvalidQuestion
		}
		if nextOffset+4 > len(data) {
			return offset, ErrInvalidQuestion
		}
		offset = nextOffset + 4
	}

	return offset, nil
}

func skipResourceRecords(data []byte, offset int, count int) (int, error) {
	for range count {
		nextOffset, err := skipName(data, offset)
		if err != nil {
			return offset, ErrInvalidAnswer
		}
		if nextOffset+10 > len(data) {
			return offset, ErrInvalidAnswer
		}

		rdLen := int(binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]))
		recordEnd := nextOffset + 10 + rdLen
		if recordEnd > len(data) {
			return offset, ErrInvalidAnswer
		}

		offset = recordEnd
	}

	return offset, nil
}

func extractRawOPTRecords(data []byte, offset int, count int) ([][]byte, int, error) {
	if count == 0 {
		return nil, offset, nil
	}

	records := make([][]byte, 0, count)
	for range count {
		recordStart := offset

		nextOffset, err := skipName(data, offset)
		if err != nil {
			return nil, offset, ErrInvalidAnswer
		}
		if nextOffset+10 > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		recordType := binary.BigEndian.Uint16(data[nextOffset : nextOffset+2])
		rdLen := int(binary.BigEndian.Uint16(data[nextOffset+8 : nextOffset+10]))
		recordEnd := nextOffset + 10 + rdLen
		if recordEnd > len(data) {
			return nil, offset, ErrInvalidAnswer
		}

		if recordType == Enums.DNS_RECORD_TYPE_OPT {
			records = append(records, data[recordStart:recordEnd])
		}

		offset = recordEnd
	}

	return records, offset, nil
}

func skipName(data []byte, offset int) (int, error) {
	if offset >= len(data) {
		return offset, ErrInvalidName
	}

	pointerJumps := 0
	for {
		if offset >= len(data) {
			return offset, ErrInvalidName
		}

		length := int(data[offset])
		if length == 0 {
			return offset + 1, nil
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) || pointerJumps >= maxNameJumps {
				return offset, ErrInvalidName
			}

			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if ptr >= len(data) {
				return offset, ErrInvalidName
			}

			return offset + 2, nil
		}

		if length > 63 {
			return offset, ErrInvalidName
		}

		offset++
		if offset+length > len(data) {
			return offset, ErrInvalidName
		}
		offset += length
	}
}
