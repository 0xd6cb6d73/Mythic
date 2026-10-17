// This executable is an interoperability fixture, not a cryptographic provider.
// It uses only the standard library and a reversible byte prefix to exercise
// lifecycle, opaque byte round trips, JSON encoding, and result replay.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

type request struct {
	APIVersion       int             `json:"api_version"`
	RequestID        string          `json:"request_id"`
	OperationScopeID int             `json:"operation_scope_id"`
	Method           string          `json:"method"`
	Scheme           string          `json:"scheme,omitempty"`
	ProfileRef       string          `json:"profile_ref,omitempty"`
	SessionRef       string          `json:"session_ref,omitempty"`
	Namespace        string          `json:"namespace,omitempty"`
	StateID          string          `json:"state_id,omitempty"`
	PayloadUUID      string          `json:"payload_uuid,omitempty"`
	NextUUID         string          `json:"next_uuid,omitempty"`
	Message          []byte          `json:"message,omitempty"`
	ProviderJSON     json.RawMessage `json:"provider_json,omitempty"`
	LookupRequestID  string          `json:"lookup_request_id,omitempty"`
	AuthContext      string          `json:"auth_context,omitempty"`
}

type failure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Outcome string `json:"outcome,omitempty"`
}

type response struct {
	APIVersion       int             `json:"api_version"`
	RequestID        string          `json:"request_id"`
	OperationScopeID int             `json:"operation_scope_id"`
	Success          bool            `json:"success"`
	Error            *failure        `json:"error,omitempty"`
	ProfileRef       string          `json:"profile_ref,omitempty"`
	SessionRef       string          `json:"session_ref,omitempty"`
	Namespace        string          `json:"namespace,omitempty"`
	StateID          string          `json:"state_id,omitempty"`
	Message          []byte          `json:"message,omitempty"`
	AgentConfig      []byte          `json:"agent_config,omitempty"`
	ProviderJSON     json.RawMessage `json:"provider_json,omitempty"`
	AuthContext      string          `json:"auth_context,omitempty"`
}

type cached struct {
	digest [32]byte
	result response
}

type session struct {
	operation int
	profile   string
	revoked   bool
}

type worker struct {
	profiles map[string]int
	sessions map[string]session
	results  map[string]cached
}

var prefix = []byte{0xf0, 0, 0x80, ':'}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fake provider rejected input")
		os.Exit(1)
	}
}

func run() error {
	w := worker{profiles: map[string]int{}, sessions: map[string]session{}, results: map[string]cached{}}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			return err
		}
		if err := encoder.Encode(w.call(req)); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (w *worker) call(req request) response {
	identity := fmt.Sprintf("%d/%s", req.OperationScopeID, req.RequestID)
	business := req
	business.AuthContext = ""
	encoded, _ := json.Marshal(business)
	digest := sha256.Sum256(encoded)
	reply := response{APIVersion: 1, RequestID: req.RequestID, OperationScopeID: req.OperationScopeID, Success: true}
	if previous, found := w.results[identity]; found {
		if previous.digest != digest {
			reply.Success = false
			reply.Error = &failure{Code: "operation_conflict", Message: "request ID was used for different input", Outcome: "rejected"}
		} else {
			reply = previous.result
		}
		reply.AuthContext = req.AuthContext
		return reply
	}
	fail := func(code string) {
		reply.Success = false
		reply.Error = &failure{Code: code, Message: "fixture operation failed", Outcome: "rejected"}
	}
	switch req.Method {
	case "describe":
		reply.ProviderJSON = json.RawMessage(`{"capabilities":{"api_version":1,"schemes":["fixture"],"establishment":"single_round","session_persistence":"volatile","max_message_bytes":1048576,"result_retention_seconds":60}}`)
	case "prepare_profile":
		if req.Scheme != "fixture" {
			fail("unsupported_scheme")
			break
		}
		reply.ProfileRef = "profile-" + req.RequestID
		w.profiles[reply.ProfileRef] = req.OperationScopeID
		reply.AgentConfig = []byte{0, 255, 128, '{'}
		reply.ProviderJSON = json.RawMessage(`{"extension":{"fixture":true}}`)
	case "begin_session":
		if w.profiles[req.ProfileRef] != req.OperationScopeID || len(req.Message) == 0 {
			fail("profile_unavailable")
			break
		}
		reply.ProfileRef = req.ProfileRef
		reply.SessionRef = "session-" + req.RequestID
		reply.Namespace, reply.StateID = "fixture", req.ProfileRef
		reply.Message = append([]byte("established:"), req.Message...)
		w.sessions[reply.SessionRef] = session{operation: req.OperationScopeID, profile: req.ProfileRef}
	case "open", "seal", "revoke_session":
		s, found := w.sessions[req.SessionRef]
		if !found || s.operation != req.OperationScopeID || s.revoked || req.Namespace != "fixture" || req.StateID != s.profile {
			fail("session_unavailable")
			break
		}
		reply.SessionRef, reply.Namespace, reply.StateID = req.SessionRef, req.Namespace, req.StateID
		if req.Method == "revoke_session" {
			s.revoked = true
			w.sessions[req.SessionRef] = s
		} else if req.Method == "seal" {
			reply.Message = append(append([]byte(nil), prefix...), req.Message...)
		} else if bytes.HasPrefix(req.Message, prefix) {
			reply.Message = append([]byte(nil), req.Message[len(prefix):]...)
		} else {
			fail("authentication_failed")
		}
	case "get_operation":
		previous, found := w.results[fmt.Sprintf("%d/%s", req.OperationScopeID, req.LookupRequestID)]
		if !found {
			fail("operation_unavailable")
			reply.Error.Outcome = "unresolved"
		} else {
			reply = previous.result
			reply.RequestID = req.RequestID
		}
	default:
		fail("unsupported_method")
	}
	w.results[identity] = cached{digest: digest, result: reply}
	reply.AuthContext = req.AuthContext
	return reply
}
