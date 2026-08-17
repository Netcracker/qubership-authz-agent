-- Copyright 2024-2026 Netcracker Technology Corporation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local function skip_ws(text, idx)
  local i = idx
  while i <= #text do
    local ch = string.sub(text, i, i)
    if ch == " " or ch == "\n" or ch == "\r" or ch == "\t" then
      i = i + 1
    else
      break
    end
  end
  return i
end

local function json_quote(value)
  local str = tostring(value or "")
  str = string.gsub(str, "\\", "\\\\")
  str = string.gsub(str, "\"", "\\\"")
  str = string.gsub(str, "\b", "\\b")
  str = string.gsub(str, "\f", "\\f")
  str = string.gsub(str, "\n", "\\n")
  str = string.gsub(str, "\r", "\\r")
  str = string.gsub(str, "\t", "\\t")
  return "\"" .. str .. "\""
end

local skip_headers = {
  [":authority"] = true, [":path"] = true, [":method"] = true, [":scheme"] = true,
  [":status"] = true, [":protocol"] = true,
  ["content-type"] = true, ["content-length"] = true, ["accept-encoding"] = true,
  ["host"] = true, ["transfer-encoding"] = true, ["connection"] = true,
  ["x-forwarded-for"] = true, ["x-forwarded-proto"] = true,
  ["x-request-id"] = true, ["x-envoy-expected-rq-timeout-ms"] = true,
  ["authorization"] = true,
  ["x-authz-original-path"] = true,
  -- ADR-0049: incoming-token is stripped from HEADER PIP resolution.
  ["incoming-token"] = true,
}

local function collect_request_headers(headers)
  local parts = {}
  for key, value in pairs(headers) do
    if not skip_headers[string.lower(key)] then
      parts[#parts + 1] = json_quote(string.lower(key)) .. ":" .. json_quote(value)
    end
  end
  if #parts == 0 then
    return "{}"
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function trim_ws(value)
  if value == nil then
    return ""
  end
  local trimmed = string.gsub(value, "^%s+", "")
  trimmed = string.gsub(trimmed, "%s+$", "")
  return trimmed
end

local function write_request_error(handle, status_code, message)
  handle:respond(
    {
      [":status"] = tostring(status_code),
      ["content-type"] = "application/json"
    },
    "{\"message\":" .. json_quote(message) .. "}"
  )
end

local function url_decode(value)
  if value == nil then
    return ""
  end

  local decoded = string.gsub(value, "+", " ")
  decoded = string.gsub(decoded, "%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  return decoded
end

local function parse_query(raw_path)
  local query = {}
  if raw_path == nil then
    return query
  end

  local q = string.find(raw_path, "?", 1, true)
  if not q then
    return query
  end

  local query_string = string.sub(raw_path, q + 1)
  for part in string.gmatch(query_string, "([^&]+)") do
    local eq = string.find(part, "=", 1, true)
    if eq then
      local key = url_decode(string.sub(part, 1, eq - 1))
      local val = url_decode(string.sub(part, eq + 1))
      query[key] = val
    else
      query[url_decode(part)] = ""
    end
  end

  return query
end

local function read_body(handle)
  local body = handle:body()
  if body == nil then
    return ""
  end
  local length = body:length()
  if length == 0 then
    return ""
  end
  local raw = body:getBytes(0, length)
  if raw == nil then
    return ""
  end
  return raw
end

local function rewrite_to_opa(handle, payload)
  handle:headers():replace(":method", "POST")
  handle:headers():replace("content-type", "application/json")
  handle:headers():remove("content-length")
  handle:headers():remove("accept-encoding")
  local body = handle:body(true)
  body:setBytes(payload)
end

local function authorization_type(headers)
  local value = headers:get("authorization-type")
  if value == nil then
    return ""
  end
  return value
end

local function is_anonymous_auth_type(auth_type)
  if auth_type == nil or auth_type == "" then
    return false
  end
  return string.lower(trim_ws(auth_type)) == "anonymous"
end

-- ADR-0049: admission token is the M2M Authorization header; the
-- policy-evaluation subject token is Incoming-Token (end-user) with
-- fallback to Authorization. Authorization-Type: anonymous forces the
-- subject to the unauthenticated marker (empty string).
local function select_admission_token(headers)
  local authorization = headers:get("authorization")
  if authorization ~= nil and authorization ~= "" then
    return authorization
  end
  return ""
end

local function select_subject_token(headers, auth_type)
  if is_anonymous_auth_type(auth_type) then
    return ""
  end

  local incoming = headers:get("incoming-token")
  if incoming ~= nil and incoming ~= "" then
    return incoming
  end

  local authorization = headers:get("authorization")
  if authorization ~= nil and authorization ~= "" then
    return authorization
  end

  return ""
end

local function scan_string(text, idx)
  local i = idx + 1
  while i <= #text do
    local ch = string.sub(text, i, i)
    if ch == "\\" then
      i = i + 2
    elseif ch == "\"" then
      return i
    else
      i = i + 1
    end
  end
  return nil
end

local function scan_composite(text, idx, open_char, close_char)
  local depth = 1
  local i = idx + 1

  while i <= #text do
    local ch = string.sub(text, i, i)
    if ch == "\"" then
      local ending = scan_string(text, i)
      if ending == nil then
        return nil
      end
      i = ending + 1
    elseif ch == open_char then
      depth = depth + 1
      i = i + 1
    elseif ch == close_char then
      depth = depth - 1
      if depth == 0 then
        return i
      end
      i = i + 1
    else
      i = i + 1
    end
  end

  return nil
end

local function scan_primitive(text, idx)
  local i = idx
  while i <= #text do
    local ch = string.sub(text, i, i)
    if ch == "," or ch == "}" or ch == "]" or ch == " " or ch == "\n" or ch == "\r" or ch == "\t" then
      return i - 1
    end
    i = i + 1
  end
  return #text
end

local function extract_field_json(raw, field_name)
  local key_pos = string.find(raw, "\"" .. field_name .. "\"", 1, true)
  if key_pos == nil then
    return nil
  end

  local i = key_pos + #field_name + 2
  i = skip_ws(raw, i)
  if string.sub(raw, i, i) ~= ":" then
    local colon = string.find(raw, ":", i, true)
    if colon == nil then
      return nil
    end
    i = colon
  end

  i = skip_ws(raw, i + 1)
  if i > #raw then
    return nil
  end

  local first = string.sub(raw, i, i)
  local ending = nil
  if first == "{" then
    ending = scan_composite(raw, i, "{", "}")
  elseif first == "[" then
    ending = scan_composite(raw, i, "[", "]")
  elseif first == "\"" then
    ending = scan_string(raw, i)
  else
    ending = scan_primitive(raw, i)
  end

  if ending == nil then
    return nil
  end

  return string.sub(raw, i, ending)
end

local function unwrap_opa_result(raw)
  return extract_field_json(raw, "result")
end

local function write_json(handle, raw_json)
  handle:headers():replace("content-type", "application/json")
  handle:headers():remove("content-length")
  handle:body():setBytes(raw_json)
end

local function write_auth_error(handle, unwrapped)
  local auth_error = extract_field_json(unwrapped, "authError")
  if auth_error == nil then
    return false
  end

  local status_json = extract_field_json(auth_error, "status")
  local message_json = extract_field_json(auth_error, "message")

  local status_code = tonumber(status_json or "401")
  if status_code == nil then
    status_code = 401
  end

  if message_json == nil then
    message_json = "\"unauthorized\""
  end

  handle:headers():replace(":status", tostring(status_code))
  write_json(handle, "{\"message\":" .. message_json .. "}")
  return true
end

-- Unquote a JSON string token, returning the raw string value.
local function unquote_json_string(field_json)
  if field_json == nil then
    return ""
  end
  local s = trim_ws(field_json)
  if #s >= 2 and string.sub(s, 1, 1) == "\"" and string.sub(s, -1) == "\"" then
    local inner = string.sub(s, 2, -2)
    inner = string.gsub(inner, "\\\"", "\"")
    inner = string.gsub(inner, "\\\\", "\\")
    return inner
  end
  return s
end

-- Find a predicate raw JSON value from a canonical predicates[] array by predicateType.
-- Returns the raw JSON value of the matching "predicate" field, or nil if not found.
local function find_predicate_by_type(predicates_json, ptype)
  if predicates_json == nil then
    return nil
  end
  local s = trim_ws(predicates_json)
  if #s < 2 or string.sub(s, 1, 1) ~= "[" then
    return nil
  end
  local i = 2
  while i <= #s do
    i = skip_ws(s, i)
    local ch = string.sub(s, i, i)
    if ch == "]" then
      break
    end
    if ch == "{" then
      local obj_end = scan_composite(s, i, "{", "}")
      if obj_end == nil then break end
      local obj = string.sub(s, i, obj_end)
      local pt_json = extract_field_json(obj, "predicateType")
      if pt_json ~= nil then
        local pt = unquote_json_string(pt_json)
        if pt == ptype then
          return extract_field_json(obj, "predicate")
        end
      end
      i = obj_end + 1
    else
      i = i + 1
    end
    i = skip_ws(s, i)
    if i <= #s and string.sub(s, i, i) == "," then
      i = i + 1
    end
  end
  return nil
end

-- Convert a raw JSON predicate value to a string for the filter response.
local function predicate_to_string(raw_value)
  if raw_value == nil then
    return ""
  end
  local s = trim_ws(raw_value)
  if #s >= 2 and string.sub(s, 1, 1) == "\"" then
    return unquote_json_string(s)
  end
  -- Object or array: return as-is (e.g. mongodb {"$or": [...]})
  return s
end

-- Build the legacy filter response object from canonical authorize result.
--
-- Per the Step 3 parity goldens
-- (tests/parity/suite/testdata/golden/check-filter-v1/*.json) the legacy
-- wire shape for the v1 check/filter response carries six fields:
--   - calculationResult ∈ {ALLOW, DENY, USE_FILTER_CONDITION}
--   - filterCondition (string) — always "" on the simplified-policy path
--     (legacy populates this only for regular full-policy `predicate`
--     templates, which row 4 / ADR-0051 permanently defers)
--   - mongodbFilterCondition (string) — canonical `mongodb` predicate, else ""
--   - rsqlFilterCondition (string) — canonical `rsql` predicate, else ""
--   - sqlFilterCondition (string) — canonical `sql` predicate, else ""
--   - customFilterCondition (JSON null | string) — legacy emits JSON null
--     in every simplified-policy golden; populated only when a `custom`
--     predicate type is produced (not emitted by the current simplified-
--     format rls.rego path, so Envoy Lua always writes null here).
local function build_filter_response(first_result_json)
  local deny_response = "{\"calculationResult\":\"DENY\""
    .. ",\"filterCondition\":\"\""
    .. ",\"mongodbFilterCondition\":\"\""
    .. ",\"rsqlFilterCondition\":\"\""
    .. ",\"sqlFilterCondition\":\"\""
    .. ",\"customFilterCondition\":null}"

  if first_result_json == nil then
    return deny_response
  end

  local is_allowed_json = extract_field_json(first_result_json, "isAllowed")
  local is_allowed = trim_ws(is_allowed_json or "")

  if is_allowed ~= "true" then
    return deny_response
  end

  -- ALLOW: extract predicates from canonical predicates[] array (ADR-0029).
  local predicates_json = extract_field_json(first_result_json, "predicates")

  local rsql_raw     = find_predicate_by_type(predicates_json, "rsql")
  local querydsl_raw = find_predicate_by_type(predicates_json, "querydsl")
  local mongodb_raw  = find_predicate_by_type(predicates_json, "mongodb")
  local sql_raw      = find_predicate_by_type(predicates_json, "sql")
  local custom_raw   = find_predicate_by_type(predicates_json, "custom")

  local rsql_str     = predicate_to_string(rsql_raw)
  local querydsl_str = predicate_to_string(querydsl_raw)
  local mongodb_str  = predicate_to_string(mongodb_raw)
  local sql_str      = predicate_to_string(sql_raw)
  local custom_str   = predicate_to_string(custom_raw)

  local has_typed_predicates = rsql_str ~= "" or querydsl_str ~= "" or mongodb_str ~= "" or sql_str ~= "" or custom_str ~= ""

  -- `filterCondition` carries the querydsl/CLANG predicate when one is
  -- present, matching the legacy access-control wire shape for full-policy
  -- predicate templates (row 6 / ADR-0051 parity).
  local filter_condition = "\"\""
  if querydsl_str ~= "" then
    filter_condition = json_quote(querydsl_str)
  end

  -- `customFilterCondition` defaults to JSON null per every simplified-
  -- format golden; the authz-agent rls path does not emit `custom` typed
  -- predicates today, but when a future plan adds that support Lua will
  -- switch to quoting the string here.
  local custom_field = "null"
  if custom_str ~= "" then
    custom_field = json_quote(custom_str)
  end

  if not has_typed_predicates then
    return "{\"calculationResult\":\"ALLOW\""
      .. ",\"filterCondition\":" .. filter_condition
      .. ",\"mongodbFilterCondition\":\"\""
      .. ",\"rsqlFilterCondition\":\"\""
      .. ",\"sqlFilterCondition\":\"\""
      .. ",\"customFilterCondition\":" .. custom_field
      .. "}"
  end

  return "{\"calculationResult\":\"USE_FILTER_CONDITION\""
    .. ",\"filterCondition\":" .. filter_condition
    .. ",\"mongodbFilterCondition\":" .. json_quote(mongodb_str)
    .. ",\"rsqlFilterCondition\":" .. json_quote(rsql_str)
    .. ",\"sqlFilterCondition\":" .. json_quote(sql_str)
    .. ",\"customFilterCondition\":" .. custom_field
    .. "}"
end

function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  local raw_path = headers:get(":path") or "/access/v1/check/filter"
  local query = parse_query(raw_path)
  if trim_ws(query.resourceType or "") == "" then
    write_request_error(request_handle, 400, "bad request")
    return
  end

  local operation = query.operation or ""
  if trim_ws(operation) == "" then
    operation = "ALL"
  end

  local auth_type = authorization_type(headers)
  local admission = select_admission_token(headers)
  local subject = select_subject_token(headers, auth_type)
  local req_headers = collect_request_headers(headers)
  -- ADR-0069: plumb the inbound x-request-id as a dedicated input.requestId
  -- (empty => OPA generates its own; Envoy always supplies one on this path).
  local request_id = headers:get("x-request-id") or ""

  local payload = "{\"input\":{\"authorizationToken\":"
    .. json_quote(admission)
    .. ",\"subject\":"
    .. json_quote(subject)
    .. ",\"authorizationType\":"
    .. json_quote(auth_type)
    .. ",\"requestHeaders\":"
    .. req_headers
    .. ",\"requestId\":"
    .. json_quote(request_id)
    .. ",\"resources\":[{\"resourceType\":"
    .. json_quote(query.resourceType or "")
    .. ",\"operation\":"
    .. json_quote(operation)
    .. ",\"resource\":{}}]}}"

  rewrite_to_opa(request_handle, payload)
  request_handle:headers():replace("x-authz-original-path", "/access/v1/check/filter")
end

function envoy_on_response(response_handle)
  local status = tonumber(response_handle:headers():get(":status") or "0")
  if status < 200 or status >= 300 then
    return
  end

  local raw = read_body(response_handle)
  if raw == nil or raw == "" then
    return
  end

  local unwrapped = unwrap_opa_result(raw)
  if unwrapped == nil then
    return
  end

  if write_auth_error(response_handle, unwrapped) then
    return
  end

  -- Extract first element from canonical results[].
  local results_json = extract_field_json(unwrapped, "results")
  local first_result = nil
  if results_json ~= nil then
    local i = skip_ws(results_json, 1)
    if string.sub(results_json, i, i) == "[" then
      i = i + 1
      i = skip_ws(results_json, i)
      if string.sub(results_json, i, i) == "{" then
        local obj_end = scan_composite(results_json, i, "{", "}")
        if obj_end ~= nil then
          first_result = string.sub(results_json, i, obj_end)
        end
      end
    end
  end

  write_json(response_handle, build_filter_response(first_result))
end
