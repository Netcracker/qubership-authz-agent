# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package identity

import rego.v1

default authenticate(request_input) := {
	"authenticated": false,
	"error": {
		"code": "UNAUTHORIZED",
		"message": "unauthorized",
		"reason": "unauthorized",
		"reasonCode": "",
	},
}

authenticate(request_input) := {
	"authenticated": false,
	"error": {
		"code": "UNAUTHORIZED",
		"message": validation.reason,
		"reason": validation.reason,
		"reasonCode": validation.reasonCode,
	},
} if {
	not anonymous_mode(request_input)
	subject_raw := object.get(request_input, "subject", "")
	validation := validate_token_with_reason(subject_raw)
	not validation.valid
}

authenticate(request_input) := {
	"authenticated": false,
	"error": {
		"code": "UNAUTHORIZED",
		"message": validation.reason,
		"reason": validation.reason,
		"reasonCode": validation.reasonCode,
	},
} if {
	anonymous_mode(request_input)
	subject_raw := object.get(request_input, "subject", "")

	# Exactly complementary to the anonymous-accept rule below: whitespace is
	# not a credential either, so `subject_raw != ""` would have both rules
	# firing for "   " and OPA answering with an eval conflict.
	not _is_empty_token_input(subject_raw)
	validation := validate_token_with_reason(subject_raw)
	not validation.valid
}

# Anonymous mode with NO credential at all. The guard is "the subject is empty",
# not "the subject is not a Bearer token": with the looser test this rule and the
# anonymous-with-invalid-token rule above both fired for a subject like
# `Basic abc` — two different values for one input, which OPA answers with an
# eval_conflict_error, i.e. a 5xx to an unauthenticated caller instead of a deny.
# A non-empty subject that is not a Bearer token is a rejected credential, not an
# absent one, so it belongs to the rule above.
authenticate(request_input) := {
	"authenticated": true,
	"subject": anonymous_subject,
	"tokenPayload": {},
} if {
	anonymous_mode(request_input)
	subject_raw := object.get(request_input, "subject", "")
	_is_empty_token_input(subject_raw)
}

authenticate(request_input) := {
	"authenticated": true,
	"subject": subject_ctx,
	"tokenPayload": object.get(verification, "payload", {}),
} if {
	subject_raw := object.get(request_input, "subject", "")
	token := bearer_token(subject_raw)
	token != ""

	verification := verify_token(token)
	verification.valid

	subject_ctx := subject_from_verification(verification)
}

verify_token(token) := {
	"valid": true,
	"header": cached_header,
	"payload": cached_payload,
	"providerId": cached_provider_id,
	"subject": cached_subject,
} if {
	cached := verified_token_entries[token]
	cached_header := object.get(cached, "header", {})
	cached_payload := object.get(cached, "payload", {})
	cached_provider_id := sprintf("%v", [object.get(cached, "providerId", "")])
	cached_subject := object.get(cached, "subject", {})
}

# Cold-path verification (authz-agent-ADR-0075).
#
# The token's `kid` selects the candidate keys and nothing else does. The `iss`
# claim is not read: Keycloak reports the issuer as the host the request arrived
# through, so the same realm reached via the in-cluster Service, the private
# gateway and the public gateway mints three different issuer strings. Trust
# rests entirely on a signature verifying against a key that bootstrap fetched
# from a configured provider.
#
# One `kid` may legitimately resolve to several keys — two realms are free to
# choose the same identifier — so every candidate is tried and the first one
# whose signature verifies wins. `successful_verifications` collects them in
# index order rather than binding inside this rule body, because a complete rule
# that produced two different `providerId` values for one token would be an
# evaluation conflict, not a decision.
verify_token(token) := {
	"valid": true,
	"header": verified.header,
	"payload": verified.payload,
	"providerId": verified.providerId,
} if {
	not verified_token_entries[token]
	decoded := decoded_token(token)
	asymmetric_alg(upper(object.get(decoded.header, "alg", "")))

	results := successful_verifications(token, decoded.header, decoded.payload)
	count(results) > 0
	verified := results[0]
}

default verify_token(token) := {"valid": false}

successful_verifications(token, header, payload) := [outcome |
	some idx
	candidate := kid_candidates(object.get(header, "kid", ""))[idx]
	candidate_alg_matches(candidate, upper(object.get(header, "alg", "")))

	provider := provider_by_id(candidate.providerId)
	result := verify_with_provider_constraints(token, candidate.jwksJson, provider, payload)
	result.valid

	outcome := {
		"header": result.header,
		"payload": result.payload,
		"providerId": candidate.providerId,
	}
]

decoded_token(token) := {
	"header": header,
	"payload": payload,
} if {
	decoded := io.jwt.decode(token)
	header := decoded[0]
	payload := decoded[1]
}

default decoded_token(_) := {
	"header": {},
	"payload": {},
}

subject_from_verification(verification) := subject if {
	cached_subject := object.get(verification, "subject", {})
	count(object.keys(cached_subject)) > 0
	subject := canonical_subject(cached_subject)
}

subject_from_verification(verification) := subject_from_payload(payload) if {
	subject := object.get(verification, "subject", {})
	count(object.keys(subject)) == 0
	payload := object.get(verification, "payload", {})
}

subject_from_verification(verification) := subject_from_payload(verification.payload) if {
	not verification.subject
}

# `io.jwt.decode_verify` is strict in both directions: when the token carries an
# `aud` claim the constraint set MUST name an audience, and when it does not the
# constraint set MUST NOT. "No audiences configured" therefore cannot be
# expressed by leaving the constraint out — that shape rejects every token that
# happens to carry an `aud`, which is most of them. The four cases are spelled
# out instead (authz-agent-ADR-0075 §5).

# Audiences configured, token carries one: it must match.
verify_with_provider_constraints(token, cert, provider, payload) := {
	"valid": true,
	"header": header,
	"payload": payload_out,
} if {
	audiences := provider_audiences(provider)
	count(audiences) > 0
	payload.aud

	some idx
	audience := audiences[idx]
	decoded := io.jwt.decode_verify(token, {"cert": cert, "aud": audience})
	decoded[0]
	header := decoded[1]
	payload_out := decoded[2]
}

# Audiences configured, token carries none: only for a provider that opted in.
# ADR-0049's legacy-ingress relay needs it — the parity stand's
# `parity-end-user` client deliberately mints subject tokens with no audience
# while admission tokens from the same realm carry `aud=netcracker`.
verify_with_provider_constraints(token, cert, provider, payload) := {
	"valid": true,
	"header": header,
	"payload": payload_out,
} if {
	count(provider_audiences(provider)) > 0
	not payload.aud
	provider.allowMissingAud == true

	decoded := io.jwt.decode_verify(token, {"cert": cert})
	decoded[0]
	header := decoded[1]
	payload_out := decoded[2]
}

# No audiences configured, token carries one: hand the token's own audience back
# so the constraint is satisfied by construction. This is how "do not check aud"
# is expressed to a builtin that insists on an opinion.
verify_with_provider_constraints(token, cert, provider, payload) := {
	"valid": true,
	"header": header,
	"payload": payload_out,
} if {
	count(provider_audiences(provider)) == 0
	token_auds := _aud_list(payload.aud)
	count(token_auds) > 0

	decoded := io.jwt.decode_verify(token, {"cert": cert, "aud": token_auds[0]})
	decoded[0]
	header := decoded[1]
	payload_out := decoded[2]
}

# No audiences configured, token carries none.
verify_with_provider_constraints(token, cert, provider, payload) := {
	"valid": true,
	"header": header,
	"payload": payload_out,
} if {
	count(provider_audiences(provider)) == 0
	not payload.aud

	decoded := io.jwt.decode_verify(token, {"cert": cert})
	decoded[0]
	header := decoded[1]
	payload_out := decoded[2]
}

default verify_with_provider_constraints(token, cert, provider, payload) := {
	"valid": false,
	"header": {},
	"payload": {},
}

# ── Key lookup ───────────────────────────────────────────────────────────

kid_candidates(kid) := authn_data.jwksByKid[kid] if {
	kid != ""
}

default kid_candidates(_) := []

provider_by_id(provider_id) := authn_data.trustedProviders.byId[provider_id]

# With `algorithms` gone from the provider config, the algorithm is the key's
# property. The JWK's own `alg` decides when it declares one — Keycloak always
# does — and the key type decides otherwise. Both spellings reject the HS256
# key-confusion attack, where a token is signed with the RSA public key used as
# an HMAC secret: `HS256` is neither the declared `RS256` nor an `RSA` algorithm.
candidate_alg_matches(candidate, alg) if {
	declared := upper(object.get(candidate, "alg", ""))
	declared != ""
	declared == alg
}

candidate_alg_matches(candidate, alg) if {
	upper(object.get(candidate, "alg", "")) == ""
	alg_key_type[alg] == upper(object.get(candidate, "kty", ""))
}

# Named exhaustively rather than by prefix. `startswith(alg, "RS")` would also
# accept an invented `RSFOO`, which would then be handed to decode_verify — a
# check that leans on a downstream failure is not a check.
alg_key_type := {
	"RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
	"PS256": "RSA", "PS384": "RSA", "PS512": "RSA",
	"ES256": "EC", "ES384": "EC", "ES512": "EC",
	"EDDSA": "OKP",
}

# `alg: none` and every symmetric algorithm are rejected before any key is
# consulted. Without a per-provider allowlist this is the only thing standing
# between an unsigned token and the verifier.
asymmetric_alg(alg) if alg_key_type[alg]

provider_audiences(provider) := [audience |
	audiences := provider.audiences
	some idx
	audience := audiences[idx]
	audience != ""
]

verified_token_entries := authn_data.verifiedTokens if {
	authn_data.verifiedTokens
}

default verified_token_entries := {}

authn_data := data.authn if {
	data.authn
}

authn_data := {} if {
	not data.authn
}

subject_from_payload(payload) := {
	"id": subject_id(payload),
	"name": subject_name(payload),
	"type": subject_type(payload),
	"roles": payload_roles(payload),
	"scopes": payload_scopes(payload),
}

canonical_subject(subject) := {
	"id": object.get(subject, "id", ""),
	"name": object.get(subject, "name", ""),
	"type": object.get(subject, "type", "USER"),
	"roles": object.get(subject, "roles", []),
	"scopes": object.get(subject, "scopes", []),
}

default subject_id(_) := ""

subject_id(payload) := payload.sub

default subject_name(_) := ""

subject_name(payload) := payload.preferred_username if {
	payload.preferred_username
}

subject_type(payload) := "SERVICE" if {
	level := lower(payload.level)
	level == "m2m"
}

subject_type(payload) := "SERVICE" if {
	level := lower(payload.level)
	level == "external"
}

default subject_type(_) := "USER"

payload_roles(payload) := sort([role | role_set[role]]) if {
	role_set := {upper(role) |
		role := payload.realm_access.roles[_]
		role != ""
	}
}

payload_scopes(payload) := sort([scope | scope_set[scope]]) if {
	scope_from_string := {scope |
		parts := split(payload.scope, " ")
		some idx
		scope := trim(parts[idx], " \t\r\n")
		scope != ""
	}

	scope_from_scp_array := {scope |
		is_array(payload.scp)
		raw_scp := payload.scp
		some idx
		scope := trim(raw_scp[idx], " \t\r\n")
		scope != ""
	}

	scope_from_scp_string := {scope |
		is_string(payload.scp)
		parts := split(payload.scp, " ")
		some idx
		scope := trim(parts[idx], " \t\r\n")
		scope != ""
	}

	scope_set := (scope_from_string | scope_from_scp_array) | scope_from_scp_string
}

anonymous_mode(request_input) if {
	lower(request_input.authorizationType) == "anonymous"
}

anonymous_mode(request_input) if {
	lower(request_input.authType) == "anonymous"
}

anonymous_subject := {
	"id": "",
	"name": "",
	"type": "ANONYMOUS",
	"roles": [],
	"scopes": [],
}

bearer_token(subject) := token if {
	is_string(subject)
	count(subject) > 7
	startswith(lower(subject), "bearer ")
	token := substring(subject, 7, -1)
}

default bearer_token(_) := ""

# ── Token validation with detailed error reasons ─────────────────────────

validate_token_with_reason(raw) := {
	"valid": true,
	"header": verification.header,
	"payload": verification.payload,
	"providerId": verification.providerId,
	"subject": object.get(verification, "subject", {}),
} if {
	verification := token_verification(raw)
	verification.valid
}

validate_token_with_reason(raw) := {
	"valid": false,
	"reasonCode": error_result.reasonCode,
	"reason": error_result.reason,
} if {
	verification := token_verification(raw)
	not verification.valid
	token := bearer_token(raw)
	error_result := _primary_token_error(raw, token, verification)
}

default validate_token_with_reason(_) := {
	"valid": false,
	"reasonCode": "TOKEN_READ_FAILED",
	"reason": "Token cannot be read",
}

token_verification(raw) := verification if {
	token := bearer_token(raw)
	token != ""
	verification := verify_token(token)
}

token_verification(raw) := {"valid": false} if {
	bearer_token(raw) == ""
}

_primary_token_error(raw_str, token, verification) := {
	"priority": 10,
	"reasonCode": "TOKEN_MISSING",
	"reason": "Authorization token is missing",
} if {
	_is_empty_token_input(raw_str)
}

_primary_token_error(raw_str, token, verification) := {
	"priority": 20,
	"reasonCode": "TOKEN_SCHEME_INVALID",
	"reason": "Authorization scheme must be Bearer",
} if {
	_is_non_bearer_scheme(raw_str)
}

_primary_token_error(raw_str, token, verification) := {
	"priority": 30,
	"reasonCode": "TOKEN_FORMAT_INVALID",
	"reason": "Token is not a valid JWT",
} if {
	token != ""
	not _is_non_bearer_scheme(raw_str)
	not _can_decode_jwt(token)
}

_primary_token_error(raw_str, token, verification) := error if {
	token != ""
	not _is_non_bearer_scheme(raw_str)
	_can_decode_jwt(token)
	decoded := decoded_token(token)
	header := decoded.header
	payload := decoded.payload
	errors := _collect_token_errors(raw_str, token, header, payload, verification)
	count(errors) > 0
	min_p := min({e.priority | some e in errors})
	winners := [e | some e in errors; e.priority == min_p]
	error := winners[0]
}

default _primary_token_error(_, _, _) := {
	"priority": 999,
	"reasonCode": "TOKEN_READ_FAILED",
	"reason": "Token cannot be read",
}

_can_decode_jwt(token) if {
	decoded := decoded_token(token)
	header := decoded.header
	payload := decoded.payload
	is_object(header)
	is_object(payload)
	count(object.keys(header)) > 0
}

_collect_token_errors(raw_str, token, header, payload, verification) := union({{e |
	_is_empty_token_input(raw_str)
	e := {"priority": 10, "reasonCode": "TOKEN_MISSING", "reason": "Authorization token is missing"}
}, {e |
	_is_non_bearer_scheme(raw_str)
	e := {"priority": 20, "reasonCode": "TOKEN_SCHEME_INVALID", "reason": "Authorization scheme must be Bearer"}
}, {e |
	token != ""
	count(object.keys(header)) == 0
	e := {"priority": 30, "reasonCode": "TOKEN_FORMAT_INVALID", "reason": "Token is not a valid JWT"}
}, {e |
	token != ""
	not asymmetric_alg(upper(object.get(header, "alg", "")))
	e := {"priority": 40, "reasonCode": "TOKEN_ALG_NOT_ALLOWED", "reason": "JWT algorithm is not allowed by trusted provider"}
}, {e |
	token != ""
	object.get(header, "kid", "") == ""
	e := {"priority": 50, "reasonCode": "TOKEN_KID_MISSING", "reason": "JWT header does not contain required kid"}
}, {e |
	token != ""
	kid := object.get(header, "kid", "")
	kid != ""
	count(kid_candidates(kid)) == 0
	e := {"priority": 60, "reasonCode": "TOKEN_KID_UNKNOWN", "reason": "JWT kid is not found in trusted provider keys"}
}, {e |
	token != ""
	kid := header.kid
	alg := upper(object.get(header, "alg", ""))
	count(kid_candidates(kid)) > 0
	count([c | some i; c := kid_candidates(kid)[i]; candidate_alg_matches(c, alg)]) == 0
	e := {"priority": 70, "reasonCode": "TOKEN_ALG_NOT_ALLOWED", "reason": "JWT algorithm is not allowed by trusted provider"}
}, {e |
	token != ""
	not payload.aud
	some provider in _candidate_providers(header)
	count(provider_audiences(provider)) > 0
	not provider.allowMissingAud == true
	e := {"priority": 90, "reasonCode": "TOKEN_AUDIENCE_MISSING", "reason": "JWT does not contain aud claim"}
}, {e |
	token != ""
	token_auds := _aud_list(payload.aud)
	count(token_auds) > 0
	some provider in _candidate_providers(header)
	audiences := provider_audiences(provider)
	count(audiences) > 0
	not _aud_match(token_auds, audiences)
	e := {"priority": 100, "reasonCode": "TOKEN_AUDIENCE_INVALID", "reason": "JWT audience is not allowed by trusted provider"}
}, {e |
	token != ""
	_exp_in_past(payload)
	e := {"priority": 110, "reasonCode": "TOKEN_EXPIRED", "reason": "Token has expired"}
}, {e |
	token != ""
	not _exp_in_past(payload)
	_nbf_in_future(payload)
	e := {"priority": 120, "reasonCode": "TOKEN_NOT_YET_VALID", "reason": "Token is not yet valid"}
}, {e |
	token != ""
	not _exp_in_past(payload)
	not _nbf_in_future(payload)
	_iat_in_future(payload)
	e := {"priority": 130, "reasonCode": "TOKEN_IAT_INVALID", "reason": "Token iat claim is invalid"}
}, {e |
	token != ""
	kid := header.kid
	alg := upper(object.get(header, "alg", ""))
	count([c | some i; c := kid_candidates(kid)[i]; candidate_alg_matches(c, alg)]) > 0
	not _exp_in_past(payload)
	not _nbf_in_future(payload)
	not verification.valid
	e := {"priority": 140, "reasonCode": "TOKEN_SIGNATURE_INVALID", "reason": "JWT signature verification failed"}
}})

# ── Error-detection helpers ──────────────────────────────────────────────

_is_empty_token_input(raw_str) if {
	is_string(raw_str)
	trim(raw_str, " \t\r\n") == ""
}

_is_non_bearer_scheme(raw_str) if {
	is_string(raw_str)
	trim(raw_str, " \t\r\n") != ""
	not startswith(lower(raw_str), "bearer ")
}

# The providers reachable from this token's kid. Used only by the error rules:
# when verification has already failed, "which provider would have been asked"
# is what turns a bare rejection into something an operator can act on.
_candidate_providers(header) := [provider |
	some idx
	candidate := kid_candidates(object.get(header, "kid", ""))[idx]
	provider := provider_by_id(candidate.providerId)
]

_exp_in_past(payload) if {
	exp := payload.exp
	is_number(exp)
	now_s := time.now_ns() / 1000000000
	exp < now_s
}

_nbf_in_future(payload) if {
	nbf := payload.nbf
	is_number(nbf)
	now_s := time.now_ns() / 1000000000
	nbf > now_s
}

_iat_in_future(payload) if {
	iat := payload.iat
	is_number(iat)
	now_s := time.now_ns() / 1000000000
	iat > now_s + 300
}

_aud_list(raw) := [raw] if {
	is_string(raw)
	raw != ""
}

_aud_list(raw) := [a |
	some idx
	a := raw[idx]
	a != ""
] if {
	is_array(raw)
}

default _aud_list(_) := []

_aud_match(token_auds, provider_auds) if {
	some tidx
	some pidx
	lower(token_auds[tidx]) == lower(provider_auds[pidx])
}
