// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"masterdnsvpn-go/internal/dnscache"
	DnsParser "masterdnsvpn-go/internal/dnsparser"
)

type dnsDispatchRequest struct {
	CacheKey []byte
	Query    []byte
	Domain   string
	QType    uint16
	QClass   uint16
}

type dnsQueryMetadata struct {
	Domain string
	QType  uint16
	QClass uint16
	Parsed DnsParser.LitePacket
}

func (c *Client) handleDNSQueryPacket(query []byte) ([]byte, *dnsDispatchRequest) {
	if !DnsParser.LooksLikeDNSRequest(query) {
		return nil, nil
	}

	metadata, ok := parseDNSQueryMetadata(query)
	if !ok {
		response, err := DnsParser.BuildFormatErrorResponse(query)
		if err != nil {
			return nil, nil
		}
		return response, nil
	}

	cacheKey := dnscache.BuildKey(metadata.Domain, metadata.QType, metadata.QClass)
	now := c.now()
	if cached, ok := c.localDNSCache.GetReady(cacheKey, query, now); ok {
		return cached, nil
	}

	result := c.localDNSCache.LookupOrCreatePending(cacheKey, metadata.Domain, metadata.QType, metadata.QClass, now)
	response, err := DnsParser.BuildServerFailureResponseFromLite(query, metadata.Parsed)
	if err != nil {
		response = nil
	}
	if !result.DispatchNeeded {
		return response, nil
	}

	dispatch := &dnsDispatchRequest{
		CacheKey: append([]byte(nil), cacheKey...),
		Query:    append([]byte(nil), query...),
		Domain:   metadata.Domain,
		QType:    metadata.QType,
		QClass:   metadata.QClass,
	}
	return response, dispatch
}

func parseDNSQueryMetadata(query []byte) (dnsQueryMetadata, bool) {
	parsed, err := DnsParser.ParsePacketLite(query)
	if err != nil || !parsed.HasQuestion {
		return dnsQueryMetadata{}, false
	}

	question := parsed.FirstQuestion
	return dnsQueryMetadata{
		Domain: question.Name,
		QType:  question.Type,
		QClass: question.Class,
		Parsed: parsed,
	}, true
}
