package ntlm

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"github.com/dop251/goja"
	"github.com/vadimi/go-http-ntlm/v2" // Correct import for version 2
	"go.k6.io/k6/js/modules"
)

// Register the NTLM module with K6
func init() {
	modules.Register("k6/x/ntlm", new(Ntlm))
}

// Ntlm struct is the entry point for your NTLM extension
type Ntlm struct{}

// Ensure Ntlm implements modules.Exporter
var _ modules.Module = &Ntlm{}

// Exports returns the exported functions for the JS runtime
func (n *Ntlm) Exports() modules.Exports {
	return modules.Exports{
		"ntlmRequest": n.NtlmRequest,
	}
}

// NtlmCredentials holds NTLM credential information
type NtlmCredentials struct {
	Username string
	Password string
	Domain   string
}

// NtlmRequest is the function that will be accessible from K6
func (n *Ntlm) NtlmRequest(call goja.FunctionCall) goja.Value {
	runtime := call.Runtime

	// Extract arguments from the call
	if len(call.Arguments) != 4 {
		panic(runtime.NewTypeError("NtlmRequest expects 4 arguments: credentials, url, soapAction, xmlPayload"))
	}

	// Extract credentials from JavaScript arguments
	credsObj := call.Arguments[0].ToObject(runtime)
	credentials := NtlmCredentials{
		Username: credsObj.Get("Username").String(),
		Password: credsObj.Get("Password").String(),
		Domain:   credsObj.Get("Domain").String(),
	}

	// Extract other arguments
	url := call.Arguments[1].String()
	soapAction := call.Arguments[2].String()
	xmlPayload := call.Arguments[3].String()

	// Configure HTTP client with NTLM Transport
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

	// Prepare the request body with the SOAP payload
	requestBody := bytes.NewBuffer([]byte(xmlPayload))
	req, err := http.NewRequest("POST", url, requestBody)
	if err != nil {
		panic(runtime.NewGoError(err))
	}

	// Set headers
	req.Header.Set("Content-Type", "text/xml;charset=UTF-8")
	req.Header.Set("SOAPAction", soapAction)

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		panic(runtime.NewGoError(err))
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(runtime.NewGoError(err))
	}

	return runtime.ToValue(string(body))
}
