package tls

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildDNSQueryRejectsInvalidLabels(t *testing.T) {
	if _, err := buildDNSQuery("", 65); err == nil {
		t.Fatal("expected empty domain to fail")
	}
	if _, err := buildDNSQuery("example..com", 65); err == nil {
		t.Fatal("expected empty label to fail")
	}
	tooLong := strings.Repeat("a", 64) + ".example"
	if _, err := buildDNSQuery(tooLong, 65); err == nil {
		t.Fatal("expected long label to fail")
	}
}

func TestBuildDNSQueryAcceptsTrailingDot(t *testing.T) {
	query, err := buildDNSQuery("example.com.", 65)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	if len(query) < 12 {
		t.Fatalf("query too short: %d", len(query))
	}
}

func TestParseDNSResponseForECHRejectsTruncatedQuestion(t *testing.T) {
	resp := []byte{
		0x00, 0x01, 0x81, 0x80,
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, // truncated question tail
	}
	if _, err := parseDNSResponseForECH(resp); err == nil {
		t.Fatal("expected truncated response to fail")
	}
}

func TestParseDNSResponseForECHExtractsECHConfig(t *testing.T) {
	echValue := []byte{0xde, 0xad, 0xbe, 0xef}
	resp := buildHTTPSAnswerResponse(t, echValue)
	got, err := parseDNSResponseForECH(resp)
	if err != nil {
		t.Fatalf("parseDNSResponseForECH: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(echValue)
	if got != want {
		t.Fatalf("unexpected ech value: got %q want %q", got, want)
	}
}

func TestDOHQueryLimitsResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxDOHResponseSize+1))
	}))
	defer server.Close()

	client := newDOHClient(server.URL, nil)
	if _, err := client.queryECH("example.com"); err == nil {
		t.Fatal("expected oversized doh response to fail")
	}
}

func buildHTTPSAnswerResponse(t *testing.T, echValue []byte) []byte {
	t.Helper()

	questionName := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	}
	httpSvc := buildHTTPSRData(echValue)
	resp := []byte{
		0x00, 0x01, 0x81, 0x80,
		0x00, 0x01, // qdcount
		0x00, 0x01, // ancount
		0x00, 0x00, 0x00, 0x00,
	}
	resp = append(resp, questionName...)
	resp = append(resp, 0x00, 0x41, 0x00, 0x01)
	resp = append(resp, 0xc0, 0x0c) // compressed name pointer
	resp = append(resp, 0x00, 0x41) // TYPE HTTPS
	resp = append(resp, 0x00, 0x01) // CLASS IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(httpSvc)))
	resp = append(resp, rdlen[:]...)
	resp = append(resp, httpSvc...)
	return resp
}

func buildHTTPSRData(echValue []byte) []byte {
	rdata := []byte{0x00, 0x01, 0x00} // priority=1, target name root
	var key [2]byte
	var length [2]byte
	binary.BigEndian.PutUint16(key[:], 0x0005)
	binary.BigEndian.PutUint16(length[:], uint16(len(echValue)))
	rdata = append(rdata, key[:]...)
	rdata = append(rdata, length[:]...)
	rdata = append(rdata, echValue...)
	return rdata
}
