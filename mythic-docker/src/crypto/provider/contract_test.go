package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCapabilitiesAndExplicitSelection(t *testing.T) {
	valid := Capabilities{APIVersion: 1, Schemes: []string{"fixture"}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: 4096, ResultRetentionSeconds: 60}
	if err := valid.Validate(); err != nil || !valid.Supports("fixture") || valid.Supports("unlisted") {
		t.Fatalf("valid capabilities: %v", err)
	}
	for name, mutate := range map[string]func(*Capabilities){
		"version":       func(c *Capabilities) { c.APIVersion++ },
		"establishment": func(c *Capabilities) { c.Establishment = "unknown" },
		"persistence":   func(c *Capabilities) { c.SessionPersistence = "unknown" },
		"duplicate":     func(c *Capabilities) { c.Schemes = []string{"fixture", "fixture"} },
		"invalid name":  func(c *Capabilities) { c.Schemes = []string{"bad:name"} },
		"empty schemes": func(c *Capabilities) { c.Schemes = nil },
		"message size":  func(c *Capabilities) { c.MaxMessageBytes = 0 },
		"retention":     func(c *Capabilities) { c.ResultRetentionSeconds = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid capabilities accepted")
			}
		})
	}
	name, scheme, external, err := ParseSelection("provider:fake:fixture")
	if err != nil || !external || name != "fake" || scheme != "fixture" {
		t.Fatalf("qualified selection: %q %q %t %v", name, scheme, external, err)
	}
	for _, value := range []string{"none", "aes256_hmac", "fixture", "custom", "provider"} {
		if _, _, external, err := ParseSelection(value); err != nil || external {
			t.Fatalf("existing selection %q changed: external=%t err=%v", value, external, err)
		}
	}
	for _, value := range []string{"provider:", "provider:fake", "provider::fixture", "provider:fake:", "provider:fake:fixture:extra", "provider:bad name:fixture"} {
		if _, _, external, err := ParseSelection(value); err == nil || !external {
			t.Fatalf("invalid qualified selection %q fell through: external=%t err=%v", value, external, err)
		}
	}
	if route, err := RoutingKey("fake"); err != nil || route != "fake_crypto_provider_rpc" {
		t.Fatalf("RPC routing key: %q %v", route, err)
	}
}

func TestRequestAndResponseValidation(t *testing.T) {
	request := fixtureRequest(Seal)
	request.SessionRef, request.Namespace, request.StateID = "session", "fixture", "state"
	request.Message = []byte{0, 255, 128}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Request){
		"wrong version":     func(r *Request) { r.APIVersion++ },
		"invalid request":   func(r *Request) { r.RequestID = "bad" },
		"missing scope":     func(r *Request) { r.OperationScopeID = 0 },
		"missing session":   func(r *Request) { r.SessionRef = "" },
		"missing namespace": func(r *Request) { r.Namespace = "" },
		"unknown method":    func(r *Request) { r.Method = "unknown" },
		"invalid JSON":      func(r *Request) { r.ProviderJSON = json.RawMessage(`{`) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	reply := Response{APIVersion: 1, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, Success: true, AuthContext: request.AuthContext, Message: request.Message}
	if err := reply.Validate(request); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Response){
		"response version": func(r *Response) { r.APIVersion++ },
		"response request": func(r *Response) { r.RequestID = uuid.NewString() },
		"response scope":   func(r *Response) { r.OperationScopeID++ },
		"response auth":    func(r *Response) { r.AuthContext = "different" },
		"contradiction":    func(r *Response) { r.Error = &Failure{Code: "failure"} },
		"failure shape":    func(r *Response) { r.Success = false },
		"unknown outcome":  func(r *Response) { r.Success = false; r.Error = &Failure{Code: "failed", Outcome: "unknown-value"} },
		"response JSON":    func(r *Response) { r.ProviderJSON = json.RawMessage(`{`) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := reply
			mutate(&candidate)
			if candidate.Validate(request) == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	failed := reply
	failed.Success = false
	failed.Error = &Failure{Code: "session_unavailable", Message: "fixture"}
	var remote *Failure
	if err := failed.Validate(request); !errors.As(err, &remote) || remote.Code != "session_unavailable" {
		t.Fatalf("typed provider failure lost: %v", err)
	}
	for _, outcome := range []string{"", OutcomeRejected, OutcomeUnresolved} {
		failed.Error = &Failure{Code: "session_unavailable", Outcome: outcome}
		if err := failed.Validate(request); !errors.As(err, &remote) || remote.Outcome != outcome {
			t.Fatalf("failure outcome %q was lost: %v", outcome, err)
		}
	}
	for _, method := range []string{PrepareProfile, BeginSession} {
		candidateRequest := fixtureRequest(method)
		candidateReply := Response{APIVersion: 1, RequestID: candidateRequest.RequestID, OperationScopeID: candidateRequest.OperationScopeID, AuthContext: candidateRequest.AuthContext, Success: true}
		if candidateReply.Validate(candidateRequest) == nil {
			t.Fatalf("missing %s result accepted", method)
		}
	}
	for _, method := range []string{Open, Seal, RevokeSession} {
		request.Method = method
		request.ProfileRef = "profile"
		for _, mutate := range []func(*Response){
			func(r *Response) { r.ProfileRef = "wrong-profile" },
			func(r *Response) { r.SessionRef = "wrong-session" },
			func(r *Response) { r.Namespace = "wrong-namespace" },
			func(r *Response) { r.StateID = "wrong-state" },
		} {
			candidate := reply
			mutate(&candidate)
			if candidate.Validate(request) == nil {
				t.Fatalf("%s accepted a different session identity", method)
			}
		}
	}
}

func TestRequestDigestExcludesTransientAuthAndTracksInput(t *testing.T) {
	r := fixtureRequest(Describe)
	r.ProviderJSON = json.RawMessage(`{"first":1,"second":2}`)
	digest, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.AuthContext = "renewed-context"
	if got, err := r.Digest(); err != nil || got != digest {
		t.Fatalf("transient auth changed digest: %q %v", got, err)
	}
	r.ProviderJSON = json.RawMessage(`{ "first": 1, "second": 2 }`)
	if got, err := r.Digest(); err != nil || got != digest {
		t.Fatalf("JSON encoding whitespace changed digest: %q %v", got, err)
	}
	r.ProviderJSON = json.RawMessage(`{"second":2,"first":1}`)
	if got, err := r.Digest(); err != nil || got == digest {
		t.Fatalf("reordered raw JSON unexpectedly matched original encoding: %q %v", got, err)
	}
	r.ProviderJSON = json.RawMessage(`{"first":9,"second":2}`)
	if got, err := r.Digest(); err != nil || got == digest {
		t.Fatalf("changed input reused digest: %q %v", got, err)
	}
}

func TestExternalFixtureProviderLifecycle(t *testing.T) {
	fixture := startFixtureProvider(t)
	described, err := fixture.call(fixtureRequest(Describe))
	var advertised struct {
		Capabilities Capabilities `json:"capabilities"`
	}
	if err != nil || json.Unmarshal(described.ProviderJSON, &advertised) != nil || advertised.Capabilities.Validate() != nil || !advertised.Capabilities.Supports("fixture") {
		t.Fatalf("describe external fixture: response=%+v err=%v", described, err)
	}
	profileRequest := fixtureRequest(PrepareProfile)
	profileRequest.Scheme = "fixture"
	profile, err := fixture.call(profileRequest)
	if err != nil || profile.ProfileRef == "" || !bytes.Equal(profile.AgentConfig, []byte{0, 255, 128, '{'}) {
		t.Fatalf("prepare external profile: response=%+v err=%v", profile, err)
	}
	beginRequest := fixtureRequest(BeginSession)
	beginRequest.ProfileRef, beginRequest.PayloadUUID, beginRequest.NextUUID = profile.ProfileRef, uuid.NewString(), uuid.NewString()
	beginRequest.Message = []byte{0, 255, 128}
	established, err := fixture.call(beginRequest)
	if err != nil || established.SessionRef == "" || !bytes.HasSuffix(established.Message, beginRequest.Message) {
		t.Fatalf("begin external session: response=%+v err=%v", established, err)
	}
	sealRequest := fixtureRequest(Seal)
	sealRequest.SessionRef, sealRequest.Namespace, sealRequest.StateID = established.SessionRef, established.Namespace, established.StateID
	sealRequest.Message = []byte{0, 1, 255, 128, '\n', '{', '}'}
	sealed, err := fixture.call(sealRequest)
	if err != nil {
		t.Fatal(err)
	}
	sealRequest.AuthContext = "renewed-context"
	replayed, err := fixture.call(sealRequest)
	if err != nil || !bytes.Equal(replayed.Message, sealed.Message) {
		t.Fatalf("stable retry with renewed auth: response=%+v err=%v", replayed, err)
	}
	conflict := sealRequest
	conflict.Message = []byte("changed input")
	_, err = fixture.call(conflict)
	assertFixtureFailure(t, err, "operation_conflict")
	var remote *Failure
	if !errors.As(err, &remote) || remote.Outcome != OutcomeRejected {
		t.Fatalf("fixture no-effect conflict outcome: %v", err)
	}
	lookup := fixtureRequest(GetOperation)
	lookup.LookupRequestID = sealRequest.RequestID
	lookedUp, err := fixture.call(lookup)
	if err != nil || !bytes.Equal(lookedUp.Message, sealed.Message) {
		t.Fatalf("get operation: response=%+v err=%v", lookedUp, err)
	}
	lookup.RequestID, lookup.OperationScopeID = uuid.NewString(), lookup.OperationScopeID+1
	_, err = fixture.call(lookup)
	assertFixtureFailure(t, err, "operation_unavailable")
	if !errors.As(err, &remote) || remote.Outcome != OutcomeUnresolved {
		t.Fatalf("fixture unavailable outcome: %v", err)
	}
	openRequest := fixtureRequest(Open)
	openRequest.SessionRef, openRequest.Namespace, openRequest.StateID = established.SessionRef, established.Namespace, established.StateID
	openRequest.Message = sealed.Message
	opened, err := fixture.call(openRequest)
	if err != nil || !bytes.Equal(opened.Message, sealRequest.Message) {
		t.Fatalf("opaque binary roundtrip: response=%+v err=%v", opened, err)
	}
	wrongScope := openRequest
	wrongScope.RequestID, wrongScope.OperationScopeID = uuid.NewString(), openRequest.OperationScopeID+1
	_, err = fixture.call(wrongScope)
	assertFixtureFailure(t, err, "session_unavailable")
	revoke := openRequest
	revoke.RequestID, revoke.Method, revoke.Message = uuid.NewString(), RevokeSession, nil
	if _, err := fixture.call(revoke); err != nil {
		t.Fatal(err)
	}
	openRequest.RequestID = uuid.NewString()
	_, err = fixture.call(openRequest)
	assertFixtureFailure(t, err, "session_unavailable")
}

func fixtureRequest(method string) Request {
	return Request{APIVersion: APIVersion, RequestID: uuid.NewString(), OperationScopeID: 7, Method: method, AuthContext: "transient-context"}
}

func assertFixtureFailure(t *testing.T, err error, code string) {
	t.Helper()
	var remote *Failure
	if !errors.As(err, &remote) || remote.Code != code {
		t.Fatalf("failure=%v, want code %s", err, code)
	}
}

type fixtureProvider struct {
	input  *json.Encoder
	output *json.Decoder
}

func startFixtureProvider(t *testing.T) *fixtureProvider {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "fake-provider")
	build := exec.Command("go", "build", "-o", binary, "./testdata/fake_provider.go")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build stdlib-only provider fixture: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, binary)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("fixture process: %v (%s)", err, strings.TrimSpace(stderr.String()))
		}
		cancel()
	})
	return &fixtureProvider{input: json.NewEncoder(stdin), output: json.NewDecoder(stdout)}
}

func (f *fixtureProvider) call(request Request) (Response, error) {
	if err := request.Validate(); err != nil {
		return Response{}, err
	}
	if err := f.input.Encode(request); err != nil {
		return Response{}, err
	}
	var reply Response
	if err := f.output.Decode(&reply); err != nil {
		return Response{}, errors.Join(io.ErrUnexpectedEOF, err)
	}
	return reply, reply.Validate(request)
}
