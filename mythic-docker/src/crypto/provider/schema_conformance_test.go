package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Exercise the published schema itself rather than duplicating its rules in a
// test validator. Correlation and decoded-byte limits are tested separately.
func TestSchemaContractConformance(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	data, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err = compiler.AddResource("schema.json", document); err != nil {
		t.Fatal(err)
	}
	compile := func(name string) *jsonschema.Schema {
		t.Helper()
		schema, err := compiler.Compile("schema.json#/$defs/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return schema
	}
	capabilitiesSchema := compile("Capabilities")
	requestSchema := compile("Request")
	responseSchema := compile("Response")
	stateKeySchema := compile("StateKey")
	lookupSchema := compile("LookupResultRequest")

	t.Run("capabilities", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			mutate func(*Capabilities)
			valid  bool
		}{
			{"valid", func(*Capabilities) {}, true},
			{"version", func(c *Capabilities) { c.APIVersion++ }, false},
			{"establishment", func(c *Capabilities) { c.Establishment = "multiple_rounds" }, false},
			{"persistence", func(c *Capabilities) { c.SessionPersistence = "unknown" }, false},
			{"volatile", func(c *Capabilities) { c.SessionPersistence = "volatile" }, true},
			{"no schemes", func(c *Capabilities) { c.Schemes = []string{} }, false},
			{"duplicate schemes", func(c *Capabilities) { c.Schemes = []string{"fixture", "fixture"} }, false},
			{"invalid scheme", func(c *Capabilities) { c.Schemes = []string{"bad:name"} }, false},
			{"long scheme", func(c *Capabilities) { c.Schemes = []string{strings.Repeat("a", 129)} }, false},
			{"zero maximum", func(c *Capabilities) { c.MaxMessageBytes = 0 }, false},
			{"maximum bound", func(c *Capabilities) { c.MaxMessageBytes = MaxMessageBytes }, true},
			{"oversized maximum", func(c *Capabilities) { c.MaxMessageBytes = MaxMessageBytes + 1 }, false},
			{"zero retention", func(c *Capabilities) { c.ResultRetentionSeconds = 0 }, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				value := Capabilities{APIVersion: APIVersion, Schemes: []string{"fixture"}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: 1024, ResultRetentionSeconds: 60}
				test.mutate(&value)
				assertSchemaConformance(t, capabilitiesSchema, value, value.Validate() == nil, test.valid)
			})
		}
	})

	t.Run("request", func(t *testing.T) {
		for _, method := range []string{Describe, PrepareProfile, BeginSession, Open, Seal, GetOperation, RevokeSession} {
			t.Run(method, func(t *testing.T) {
				value := schemaFixtureRequest(method)
				assertSchemaConformance(t, requestSchema, value, value.Validate() == nil, true)
			})
		}
		for _, test := range []struct {
			name, method string
			mutate       func(*Request)
		}{
			{"version", Open, func(r *Request) { r.APIVersion++ }},
			{"scope", Open, func(r *Request) { r.OperationScopeID = 0 }},
			{"unknown method", Open, func(r *Request) { r.Method = "unknown" }},
			{"uppercase request UUID", Open, func(r *Request) { r.RequestID = strings.ToUpper(r.RequestID) }},
			{"undashed lookup UUID", GetOperation, func(r *Request) { r.LookupRequestID = strings.ReplaceAll(r.LookupRequestID, "-", "") }},
			{"missing lookup", GetOperation, func(r *Request) { r.LookupRequestID = "" }},
			{"invalid optional scheme", Describe, func(r *Request) { r.Scheme = "bad:name" }},
			{"invalid optional UUID", Open, func(r *Request) { r.PayloadUUID = "invalid" }},
			{"missing scheme", PrepareProfile, func(r *Request) { r.Scheme = "" }},
			{"missing profile", BeginSession, func(r *Request) { r.ProfileRef = "" }},
			{"missing initial message", BeginSession, func(r *Request) { r.Message = nil }},
			{"missing routing claim", BeginSession, func(r *Request) { r.NextUUID = "" }},
			{"missing session", Open, func(r *Request) { r.SessionRef = "" }},
			{"missing namespace", Seal, func(r *Request) { r.Namespace = "" }},
			{"oversized reference", Open, func(r *Request) { r.ProfileRef = strings.Repeat("a", 1025) }},
		} {
			t.Run(test.name, func(t *testing.T) {
				value := schemaFixtureRequest(test.method)
				test.mutate(&value)
				assertSchemaConformance(t, requestSchema, value, value.Validate() == nil, false)
			})
		}
	})

	t.Run("response", func(t *testing.T) {
		request := schemaFixtureRequest(Open)
		for _, test := range []struct {
			name   string
			mutate func(*Response)
			valid  bool
		}{
			{"success", func(*Response) {}, true},
			{"version", func(r *Response) { r.APIVersion++ }, false},
			{"contradictory error", func(r *Response) { r.Error = &Failure{Code: "failed"} }, false},
			{"missing failure", func(r *Response) { r.Success = false }, false},
			{"failure", func(r *Response) { r.Success = false; r.Error = &Failure{Code: "failed"} }, true},
			{"rejected", func(r *Response) { r.Success = false; r.Error = &Failure{Code: "failed", Outcome: OutcomeRejected} }, true},
			{"unresolved", func(r *Response) { r.Success = false; r.Error = &Failure{Code: "failed", Outcome: OutcomeUnresolved} }, true},
			{"missing code", func(r *Response) { r.Success = false; r.Error = &Failure{} }, false},
			{"invalid outcome", func(r *Response) { r.Success = false; r.Error = &Failure{Code: "failed", Outcome: "unknown"} }, false},
			{"oversized reference", func(r *Response) { r.SessionRef = strings.Repeat("a", 1025) }, false},
		} {
			t.Run(test.name, func(t *testing.T) {
				value := Response{APIVersion: APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true, Message: []byte{0, 128, 255}}
				test.mutate(&value)
				var failure *Failure
				err := value.Validate(request)
				assertSchemaConformance(t, responseSchema, value, err == nil || errors.As(err, &failure), test.valid)
			})
		}
	})

	t.Run("failure without human description", func(t *testing.T) {
		request := schemaFixtureRequest(Open)
		wire := map[string]interface{}{
			"api_version": APIVersion, "request_id": request.RequestID,
			"operation_scope_id": request.OperationScopeID, "auth_context": request.AuthContext,
			"success": false, "error": map[string]interface{}{"code": "failed"},
		}
		data, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		var response Response
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		var failure *Failure
		assertSchemaConformance(t, responseSchema, wire, errors.As(response.Validate(request), &failure), true)
	})

	t.Run("storage key", func(t *testing.T) {
		for _, test := range []struct {
			name, namespace, stateID string
			valid                    bool
		}{
			{"valid", "campaign/1", "server", true},
			{"missing namespace", "", "server", false},
			{"invalid namespace", "campaign 1", "server", false},
			{"oversized namespace", strings.Repeat("a", 129), "server", false},
			{"missing state", "campaign/1", "", false},
			{"oversized state", "campaign/1", strings.Repeat("a", 257), false},
		} {
			t.Run(test.name, func(t *testing.T) {
				value := StateKey{Namespace: test.namespace, StateID: test.stateID}
				assertSchemaConformance(t, stateKeySchema, value, validateStateKey(1, value) == nil, test.valid)
			})
		}
	})

	t.Run("storage lookup", func(t *testing.T) {
		for _, test := range []struct {
			name, requestID, digest string
			valid                   bool
		}{
			{"valid", "request-1", strings.Repeat("a", 64), true},
			{"missing request", "", strings.Repeat("a", 64), false},
			{"invalid request", "request 1", strings.Repeat("a", 64), false},
			{"short digest", "request-1", "abcd", false},
			{"uppercase digest", "request-1", strings.Repeat("A", 64), false},
		} {
			t.Run(test.name, func(t *testing.T) {
				value := LookupResultRequest{StateKey: StateKey{Namespace: "campaign/1", StateID: "server"}, RequestID: test.requestID, InputDigest: test.digest}
				assertSchemaConformance(t, lookupSchema, value, validateLookup(1, value) == nil, test.valid)
			})
		}
	})

	t.Run("request-dependent response checks", func(t *testing.T) {
		request := schemaFixtureRequest(PrepareProfile)
		response := Response{APIVersion: APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true}
		// A standalone response schema cannot know that prepare_profile requires
		// a profile reference, or which request identity/auth token must match.
		if err := responseSchema.Validate(schemaDocument(t, response)); err != nil {
			t.Fatalf("standalone response shape rejected: %v", err)
		}
		if err := response.Validate(request); err == nil {
			t.Fatal("accepted missing method-dependent profile")
		}
		response.ProfileRef, response.RequestID = "profile", uuid.NewString()
		if err := response.Validate(request); err == nil {
			t.Fatal("accepted response to a different request")
		}
	})

	t.Run("reference byte limit", func(t *testing.T) {
		request := schemaFixtureRequest(Open)
		request.ProfileRef = strings.Repeat("é", 513)
		if err := requestSchema.Validate(schemaDocument(t, request)); err != nil {
			t.Fatalf("character-count schema rejected short Unicode reference: %v", err)
		}
		if err := request.Validate(); err == nil {
			t.Fatal("runtime accepted reference exceeding decoded UTF-8 byte limit")
		}
	})
}

func schemaFixtureRequest(method string) Request {
	return Request{
		APIVersion: APIVersion, RequestID: "0cd266dc-b8e2-453d-b8f8-bcde96d2a3df", OperationScopeID: 7,
		Method: method, Scheme: "fixture", ProfileRef: "profile", SessionRef: "session", Namespace: "campaign/7",
		PayloadUUID: "0cd266dc-b8e2-453d-b8f8-bcde96d2a3df", NextUUID: "1018e570-5d35-493e-8425-724d07e7885a",
		LookupRequestID: "1018e570-5d35-493e-8425-724d07e7885a", Message: []byte{0, 128, 255}, AuthContext: "transient-context",
	}
}

func assertSchemaConformance(t *testing.T, schema *jsonschema.Schema, value interface{}, runtimeValid, want bool) {
	t.Helper()
	schemaErr := schema.Validate(schemaDocument(t, value))
	if runtimeValid != want || (schemaErr == nil) != want {
		t.Fatalf("runtime valid=%t, schema error=%v; want valid=%t; message=%+v", runtimeValid, schemaErr, want, value)
	}
}

func schemaDocument(t *testing.T, value interface{}) interface{} {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return document
}
