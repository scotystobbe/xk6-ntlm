package ntlm

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"github.com/vadimi/go-http-ntlm/v2" // Correct import for version 2
	"go.k6.io/k6/js/modules"
)

// Register the NTLM module with K6
func init() {
	modules.Register("k6/x/ntlm", new(Ntlm))
}

// Ntlm struct is the entry point for your NTLM extension
type Ntlm struct{}

// NtlmCredentials holds NTLM credential information
type NtlmCredentials struct {
	Username string
	Password string
	Domain   string
}

// NtlmRequest is the function that will be accessible from K6
func (n *Ntlm) NtlmRequest(credentials NtlmCredentials, url string, soapAction string, xmlPayload string) (string, error) {
	client := &http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:   credentials.Domain,
			User:     credentials.Username,
			Password: credentials.Password,
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Optional, only use for testing.
				},
			},
		},
	}

	requestBody := bytes.NewBuffer([]byte(xmlPayload))
	req, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", soapAction)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
