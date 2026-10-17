# Crypto provider API v1

This internal API lets a separately deployed crypto service implement a protocol while Mythic keeps C2 transport, UUID framing, message-format processing, and callback routing. Agent wire messages do not change. Mythic passes the provider's registration, plaintext, ciphertext, and builder configuration as opaque bytes.

The Go contract is [contract.go](contract.go), the durable-storage types are [state_types.go](state_types.go), and [schema.json](schema.json) describes the JSON messages. The Go validators and this document define constraints that JSON Schema cannot express, including matching a response to its request. API v1 implements a single registration round trip. It does not implement a particular native cryptographic library.

## Registration and selection

Register the consuming container with `type: "crypto"` and `crypto_capabilities`:

```json
{
  "api_version": 1,
  "schemes": ["example"],
  "establishment": "single_round",
  "session_persistence": "durable",
  "max_message_bytes": 1048576,
  "result_retention_seconds": 3600
}
```

`session_persistence` is `durable` or `volatile`. The advertised maximum must be positive and at most 67,108,864 decoded bytes. Retention is a positive number of seconds. Scheme names are unique, start with an ASCII letter or digit, and contain at most 128 ASCII letters, digits, underscores, dots, or hyphens.

Select the provider explicitly with `provider:<registered-container-name>:<scheme>`, for example `provider:example-service:example`. Existing built-in selections retain their existing meaning. Invalid selections beginning with `provider:` are rejected.

Payload containers declare compatible external schemes in their payload-type sync definition with optional `supported_crypto_schemes: ["example"]`. Values are bare scheme identifiers, independent of a worker's registered name. The list contains at most 128 unique identifiers using the scheme naming rules above. An omitted or empty list means that the payload supports no external schemes; it does not change legacy built-in or translation-container selections. Every sync replaces the stored declaration, including resyncs that omit it. Mythic exposes this JSONB declaration read-only to operators and checks it for both build and C2 crypto parameters before asking a provider to prepare a profile. API builds, imported configurations and rebuilds use the same check. A compatible payload declaration does not replace the selected provider's own availability and capabilities checks.

## Provider RPC

Mythic publishes plain JSON requests on exchange `mythic_exchange`, routing key `<registered-container-name>_crypto_provider_rpc`, using its existing AMQP RPC reply/correlation mechanism. Responses are plain JSON objects too. The worker owns that RPC queue. Binary fields use padded RFC 4648 standard base64.

Authorization uses Mythic's existing `mythic-auth-context` AMQP header. Mythic creates a transient `mctx_` token for each synchronous request, bound internally to its operation and the selected registered container. The request's `auth_context` is the same token. The provider adapter requires the header and body tokens to match, echoes the body token in its response, and propagates the incoming header on nested storage calls. This context expires when the synchronous call completes, including transport failure; it is not a deployment secret or durable business result.

Mythic, the provider, the database, and the messaging infrastructure are trusted components. The API adds no application-level signature, MAC envelope, shared key, or confidentiality layer. RabbitMQ connection credentials and access controls remain deployment configuration.

Requests contain:

| Field | Meaning |
| --- | --- |
| `api_version` | `1` |
| `request_id` | Canonical lowercase UUID, retained across retries |
| `operation_scope_id` | Positive Mythic operation ID |
| `method` | One of the methods below |
| `scheme`, `profile_ref`, `session_ref` | Scheme and opaque provider references as applicable |
| `namespace`, `state_id` | Opaque durable state scope as applicable |
| `payload_uuid`, `next_uuid` | Canonical UUID routing claims for session establishment |
| `message` | Opaque bytes, base64 encoded |
| `provider_json` | Optional provider extension data |
| `lookup_request_id` | Original request UUID for `get_operation` |
| `auth_context` | Transient Mythic authorization context |

References have a 1,024-byte maximum at this boundary. Request/response messages, builder configuration, and provider JSON each have a 67,108,864-byte maximum, with additional JSON encoding and transport bounds. A provider may advertise a smaller message maximum.

Responses include `api_version`, the request's exact `request_id`, `operation_scope_id`, `auth_context`, and `success`. A failed response contains `error: {"code": "<provider-code>", "message": "<description>"}`. A successful response must omit `error`. Mythic rejects replies with mismatched request, operation, or authorization context. For `open`, `seal`, and `revoke_session`, any returned nonempty profile/session/state references must also match the request. Providers must authorize every profile/session reference within the requested operation; the transient transport context does not establish ownership of arbitrary references.

Failures may include `error.outcome: "rejected"` or `"unresolved"`. `rejected` explicitly promises that continuing the session is safe and this failure leaves no unresolved cryptographic effect. `unresolved` means the caller cannot safely assume that promise. For `open` and `seal`, an omitted or empty outcome also means unresolved. Other nonempty outcomes are invalid. A failure report does not establish that native work had no effect unless it explicitly makes that promise.

| Method | Required request data | Successful response |
| --- | --- | --- |
| `describe` | Common request fields | Provider extension data; capability advertisement is supplied during consuming-container sync |
| `prepare_profile` | `scheme` | Nonempty `profile_ref`; optional `agent_config`, `provider_json`, `namespace`, `state_id`, `enc_key`, `dec_key` |
| `begin_session` | `profile_ref`, nonempty `message`, `payload_uuid`, `next_uuid` | Nonempty `session_ref`, `namespace`, and reply `message`; optional `state_id`, `provider_json` |
| `open` | `session_ref`, `namespace`, opaque `message`; state/profile references from the binding | Plaintext `message` |
| `seal` | `session_ref`, `namespace`, plaintext `message`; state/profile references from the binding | Opaque encrypted `message` |
| `get_operation` | `lookup_request_id` | The prior business result, correlated to the current lookup request |
| `revoke_session` | `session_ref`, `namespace`; state reference from the binding | Provider-specific revocation result |

`agent_config` contains arbitrary provider-defined bytes; its wire representation is standard base64. Mythic stores the raw bytes and projects them into builder JSON as the base64 string `provider_config`. A builder decodes that string to recover the exact configuration bytes, then interprets them according to its selected provider. `enc_key` and `dec_key` are optional compatibility fields; their bytes are also base64 encoded. Providers decide whether they are needed. Mythic stores profile/session references and extension JSON without interpreting native cryptographic state.

For `begin_session`, Mythic supplies an already allocated next routing UUID. The provider interprets the opaque initial message and produces its protocol's response, including whatever authenticated binding to that UUID the protocol requires. Mythic preserves its existing outer UUID/base64 envelope and normal check-in/callback transitions.

## Retries and operation results

Mythic preserves a serialized request and request ID across AMQP timeout retries. Providers must detect reuse of the same request ID with different input and must return the saved outcome for an identical completed request instead of repeating cryptographic work.

The Go `Request.Digest` computes SHA-256 over its JSON encoding with `auth_context` cleared. It excludes transient authorization context. Its JSON encoder normalizes whitespace in `provider_json`; member ordering and changed values can still change the digest. Implementations using this digest must preserve the original field representation and use the same encoding rules, or retain the digest supplied by their own adapter consistently. The digest is represented as 64 lowercase hexadecimal characters for storage calls.

The same completed business result may be replayed with renewed transient authorization metadata. Echo the current request's `auth_context`; do not persist an expired token as an immutable part of the business outcome. A `get_operation` reply is correlated to its current lookup request ID and operation scope. Providers own recovery, expiration, and revocation semantics within their advertised retention period.

Providers own native state serialization, failure fencing, and session recovery. Mythic passes correlated `open` and `seal` requests and propagates their outcomes; an RPC acknowledgement failure does not impose a server-owned cryptographic session policy. Providers must retain completed results for exact request retries.

For callback request/reply traffic, Mythic retains the exact sealed response keyed by the session binding, routing UUID, and incoming ciphertext digest. An identical transport retry returns that response without opening or dispatching the message again. Mythic saves the exact serialized application response before sealing, so a lost provider acknowledgement can resume the same seal request after restart. A short database transaction admits one application dispatch per route across Mythic backends. Competing authenticated packets receive a retryable dispatch conflict; the provider retains their `open` results under their original request IDs. No database transaction is held across provider RPC or application dispatch. A crash after the dispatch claim but before saving the application response leaves that exchange unresolved; Mythic cannot safely repeat application effects and rejects new packets on that route. This ledger does not provide exactly-once task execution across process crashes.

Delegated/P2P traffic through a polling egress uses the same provider registration, `open`, and `seal` operations as direct traffic. Each callback keeps its own opaque session binding, independently of the egress callback's encryption. Provider-managed P2P callbacks can therefore traverse an AESPSK or provider-managed polling egress, and provider-managed polling egress callbacks can relay either kind of P2P callback. TCP P2P through HTTP polling egress exercises all four combinations. Mythic retains its ordinary nested delegate framing and callback UUID transitions.

Each provider-managed callback retains its own incoming exchange results as described above. Legacy egress callbacks use Mythic's existing transport delivery behavior. A lost enclosing transport reply can lose delegated task delivery; committing a child's cryptographic operation does not acknowledge delivery of its ciphertext. Providers and their agent protocols define their own message-loss limits.

Push processing, delegated task collection, and transport queues retain upstream Mythic behavior. Providers define their own tolerance for loss and reordering. Current end-to-end coverage exercises HTTP polling egress with TCP P2P; it does not establish push transport support for a particular provider.

## Generic Mythic storage RPC

Providers can persist authoritative state in Mythic's database. They do not need their own database. The live native handle belongs to the worker; Mythic stores exact opaque state bytes and JSONB extension data. Publish storage requests on exchange `mythic_exchange`, routing key `mythic_rpc_crypto_provider_storage`. The request body is:

```json
{
  "api_version": 1,
  "request_id": "0cd266dc-b8e2-453d-b8f8-bcde96d2a3df",
  "provider_name": "example-service",
  "method": "load",
  "input": {"namespace": "identity", "state_id": "server-1"}
}
```

Propagate the current provider request's `mythic-auth-context` AMQP header. Mythic validates that token and requires its internally bound container name to match `provider_name`; an ordinary operator token or a caller-supplied name alone cannot grant storage access. It resolves the registered, non-deleted `crypto` service's database ID internally and uses that ID to scope every state query. Providers initialize campaign state lazily during a scoped request; storage is unavailable outside a live request context. The provider is responsible for keeping its state keys and profile/session ownership within the current operation.

Each storage `request_id` is a canonical UUID and is distinct from the immutable operation `input.request_id` used by `commit` and `get_result`.

Storage responses are plain JSON with `api_version`, the exact request's `request_id` and `provider_name`, and either `success: true, result: ...` or `success: false, error: {code, message}`. Check these correlation fields. Error codes are `invalid_input`, `not_found`, `already_exists`, `stale_writer`, `request_conflict`, `internal_error`, and `unauthorized`. Malformed or unauthorized requests may receive a generic rejection without correlation fields; callers must treat those responses as unresolved, not as trusted operation outcomes. Native state and operation results are never ordinary operator/UI fields.

All methods address a stable `namespace` and `state_id`. Namespace, state ID, and request ID use ASCII letters, digits, `.`, `_`, `:`, `/`, or `-`. Their respective byte limits are 128, 256, and 128. A state blob has a 16 MiB limit, provider JSON a 1 MiB limit, and result JSON a 16 MiB limit.

| Method | Input in addition to `namespace`, `state_id` | Result |
| --- | --- | --- |
| `load` | None | `state_blob`, `provider_json`, `revision`, `owner_epoch`, `updated_at`, and scope fields |
| `create` | `state_blob`; optional object `provider_json` (default `{}`) | Newly created state at revision/epoch zero; existing state is an error |
| `acquire` | `expected_owner_epoch` | State with epoch incremented only if the supplied epoch matches; revision is unchanged |
| `commit` | `owner_epoch`, `expected_revision`, `request_id`, `input_digest`, `state_blob`, optional object `provider_json`, JSON `result` | `revision`, saved `result`, and `cached` |
| `get_result` | `request_id`, `input_digest` | Immutable operation result with scope, digest, revision, and creation time |

`state_blob` is standard-base64 of exact bytes. JSONB may normalize extension/result JSON formatting, but preserves byte strings carried inside that JSON. The first `commit` response also uses the stored result representation, matching later retries. Neither state nor operation results are silently created by `load`, `acquire`, or `commit`.

`acquire` fences previous owners by a compare-and-swap on `expected_owner_epoch`. Retrying the old epoch fails rather than incrementing again. Reconcile uncertain acknowledgements before treating an owner as acquired. Native restore and checkpoint activation remain the provider's responsibility.

`commit` locks the state row, checks for a matching immutable request result, then checks owner epoch and expected revision. A cached request/digest returns its saved result even if the supplied epoch/revision has since become stale. A reused request ID with a different digest is rejected. A new commit atomically writes the exact checkpoint bytes, extension JSON, incremented service revision, and immutable operation result. A stale writer changes nothing. Service revision and owner epoch are independent of any counters inside the native state blob.

Providers choose their own state layout, locking, and recovery policy. A successful output that depends on a state change must follow an authoritative state/result commit. An uncertain commit acknowledgement can be reconciled through `get_result`. Mythic stores opaque bytes and extension JSON without interpreting cryptographic state.

## Conformance fixture

`go test ./crypto/provider` exercises validation, plain JSON messages, binary round trips, and an external fixture process implemented using only the Go standard library. [The fixture](testdata/fake_provider.go) uses a reversible byte prefix and in-memory outcomes solely to test the interface; it is not encryption or a deployable provider. It communicates using newline-delimited JSON requests and responses on stdin/stdout to isolate wire conformance from AMQP deployment.

For real PostgreSQL transaction, rollback, and fencing tests, set `CRYPTO_PROVIDER_TEST_DSN` to an isolated database and run `go test -race ./crypto/provider`. Tests create and remove a unique schema and apply the actual crypto-provider migration.
