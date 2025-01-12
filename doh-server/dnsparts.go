package main

import (
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Response struct {
	// Standard DNS response code (32 bit integer)
	Status uint32 `json:"Status"`
	// Whether the response is truncated
	TC bool `json:"TC"`
	// Recursion desired
	RD bool `json:"RD"`
	// Recursion available
	RA bool `json:"RA"`
	// Whether all response data was validated with DNSSEC
	// FIXME: We don't have DNSSEC yet! This bit is not reliable!
	AD bool `json:"AD"`
	// Whether the client asked to disable DNSSEC
	CD               bool       `json:"CD"`
	Question         []Question `json:"Question"`
	Answer           []RR       `json:"Answer,omitempty"`
	Authority        []RR       `json:"Authority,omitempty"`
	Additional       []RR       `json:"Additional,omitempty"`
	Comment          string     `json:"Comment,omitempty"`
	EdnsClientSubnet string     `json:"edns_client_subnet,omitempty"`
	// Least time-to-live
	HaveTTL         bool      `json:"-"`
	LeastTTL        uint32    `json:"-"`
	EarliestExpires time.Time `json:"-"`
}

type Question struct {
	// FQDN with trailing dot
	Name string `json:"name"`
	// Standard DNS RR type
	Type uint16 `json:"type"`
}

type RR struct {
	Question
	// Record's time-to-live in seconds
	TTL uint32 `json:"TTL"`
	// TTL in absolute time
	Expires    time.Time `json:"-"`
	ExpiresStr string    `json:"Expires"`
	// Data
	Data string `json:"data"`
}

func (s *Server) CreateDNSPart(msg *dns.Msg, token string, tokendnsrequestid string) *Response {
	now := time.Now().UTC()
	CustomDNSAnswer := "no"
	resp := new(Response)
	resp.Status = uint32(msg.Rcode)
	resp.TC = msg.Truncated
	resp.RD = msg.RecursionDesired
	resp.RA = msg.RecursionAvailable
	resp.AD = msg.AuthenticatedData
	resp.CD = msg.CheckingDisabled

	resp.Question = make([]Question, 0, len(msg.Question))
	for _, question := range msg.Question {

		// check per question if part of the blacklist
		trimmedquestionname := strings.TrimSuffix(question.Name, ".")
		tokenanswer := s.TokenBlackListCheck(token, trimmedquestionname)

		if tokenanswer == "true" {
		} else if tokenanswer == "blackhole" {
			CustomDNSAnswer = "blacklist"
		} else if tokenanswer == "proxyrequest" {
			CustomDNSAnswer = "proxyrequest"
		}

		jsonQuestion := Question{
			Name: question.Name,
			Type: question.Qtype,
		}
		resp.Question = append(resp.Question, jsonQuestion)
	}

	resp.Answer = make([]RR, 0, len(msg.Answer))
	answercount := len(msg.Answer)

	for _, rr := range msg.Answer {
		jsonAnswer := s.marshalRR(rr, now, CustomDNSAnswer, answercount, token, tokendnsrequestid)
		if !resp.HaveTTL || jsonAnswer.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAnswer.TTL
			resp.EarliestExpires = jsonAnswer.Expires
		}
		resp.Answer = append(resp.Answer, jsonAnswer)
	}

	resp.Authority = make([]RR, 0, len(msg.Ns))
	for _, rr := range msg.Ns {
		jsonAuthority := s.marshalRR(rr, now, CustomDNSAnswer, 99, token, tokendnsrequestid)
		if !resp.HaveTTL || jsonAuthority.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAuthority.TTL
			resp.EarliestExpires = jsonAuthority.Expires
		}
		resp.Authority = append(resp.Authority, jsonAuthority)
	}

	resp.Additional = make([]RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		jsonAdditional := s.marshalRR(rr, now, CustomDNSAnswer, 99, token, tokendnsrequestid)
		header := rr.Header()
		if header.Rrtype == dns.TypeOPT {
			opt := rr.(*dns.OPT)
			resp.Status = ((opt.Hdr.Ttl & 0xff000000) >> 20) | (resp.Status & 0xff)
			continue
		}
		if !resp.HaveTTL || jsonAdditional.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAdditional.TTL
			resp.EarliestExpires = jsonAdditional.Expires
		}
		resp.Additional = append(resp.Additional, jsonAdditional)
	}

	return resp
}

func (s *Server) marshalRR(rr dns.RR, now time.Time, CustomDNSAnswer string, count int, token string, tokendnsrequestid string) RR {
	jsonRR := RR{}
	rrHeader := rr.Header()
	jsonRR.Name = rrHeader.Name
	jsonRR.Type = rrHeader.Rrtype
	jsonRR.TTL = rrHeader.Ttl
	jsonRR.Expires = now.Add(time.Duration(jsonRR.TTL) * time.Second)
	jsonRR.ExpiresStr = jsonRR.Expires.Format(time.RFC1123)
	data := strings.SplitN(rr.String(), "\t", 5)
	if len(data) >= 5 {

		// check if data is IP. If not record can be txt or else.
		if s.ReturnIPAddress(data[4]) == "" {
			// request is not an IP so return the answer in json
			jsonRR.Data = data[4]
		} else {
			if CustomDNSAnswer == "blacklist" {
				jsonRR.Data = "0.0.0.0"
			} else {
				jsonRR.Data = data[4]
			}
		}

		s.DNSAnswerInsert(tokendnsrequestid, data[4], count, CustomDNSAnswer)
	}
	return jsonRR
}

func (s *Server) ReturnIPAddress(input string) string {
	numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock

	regEx := regexp.MustCompile(regexPattern)
	return regEx.FindString(input)
}
