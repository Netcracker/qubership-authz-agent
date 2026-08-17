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

-- check_resource_v2.lua — ADR-0027-compliant legacy compatibility filter
-- for POST /access/v2/check/resource.
--
-- Legacy request shape (matches the v2 thin client DTO):
--
--   {
--     "operation": "READ",
--     "type": "Order",
--     "resource": { ... }
--   }
--
-- Query string always carries obligations=<bool> and tenant_id=<string>
-- (tenant ignored in current MVP per docs/ai/architecture.md).
--
-- Legacy response shape:
--
--   {
--     "decision": true,
--     "obligations": { ... }        // omitted in parity; ignored by decisioning
--   }
--
-- The filter rewrites the request into the canonical OPA input (single
-- resource entry), calls POST /v1/data/authorize, then projects the
-- canonical decision back into the {"decision": <bool>} wrapper.
-- Obligations are not synthesized; parity goldens exclude that field via
-- cmpopts.IgnoreFields per D-E.

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
  handle:body():setBytes(payload)
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

local function missing_required_string_field(raw, field_name)
  local field_json = extract_field_json(raw, field_name)
  if field_json == nil then
    return true
  end
  field_json = trim_ws(field_json)
  return field_json == "" or field_json == "null" or field_json == "\"\""
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

local function extract_string_value(raw, field_name)
  local field_json = extract_field_json(raw, field_name)
  if field_json == nil then
    return nil
  end
  field_json = trim_ws(field_json)
  if string.sub(field_json, 1, 1) == "\"" and #field_json >= 2 then
    return string.sub(field_json, 2, -2)
  end
  return field_json
end

function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  local auth_type = authorization_type(headers)
  local admission = select_admission_token(headers)
  local subject = select_subject_token(headers, auth_type)
  local req_headers = collect_request_headers(headers)
  -- ADR-0069: plumb the inbound x-request-id as a dedicated input.requestId
  -- (empty => OPA generates its own; Envoy always supplies one on this path).
  local request_id = headers:get("x-request-id") or ""

  local raw_body = read_body(request_handle)
  if raw_body == nil or raw_body == "" then
    write_request_error(request_handle, 400, "bad request")
    return
  end

  if missing_required_string_field(raw_body, "type") then
    write_request_error(request_handle, 400, "Missing required parameter: type")
    return
  end
  if missing_required_string_field(raw_body, "operation") then
    write_request_error(request_handle, 400, "Missing required parameter: operation")
    return
  end

  local resource_type_json = extract_field_json(raw_body, "type")
  local operation_json = extract_field_json(raw_body, "operation")
  local resource_json = extract_field_json(raw_body, "resource")
  if resource_type_json == nil then resource_type_json = "\"\"" end
  if operation_json == nil then operation_json = "\"\"" end
  if resource_json == nil then resource_json = "{}" end

  local canonical_resources = "[{\"resourceType\":"
    .. resource_type_json
    .. ",\"operation\":"
    .. operation_json
    .. ",\"resource\":"
    .. resource_json
    .. "}]"

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
    .. ",\"resources\":"
    .. canonical_resources
    .. "}}"

  rewrite_to_opa(request_handle, payload)
  request_handle:headers():replace("x-authz-original-path", "/access/v2/check/resource")
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

  -- Derive v2 decision from canonical AuthorizeResponse.results[0].isAllowed
  local results_json = extract_field_json(unwrapped, "results")
  local allowed = false
  if results_json ~= nil then
    local i = skip_ws(results_json, 1)
    if string.sub(results_json, i, i) == "[" then
      i = i + 1
      i = skip_ws(results_json, i)
      if string.sub(results_json, i, i) == "{" then
        local obj_end = scan_composite(results_json, i, "{", "}")
        if obj_end ~= nil then
          local first_result = string.sub(results_json, i, obj_end)
          local is_allowed = extract_field_json(first_result, "isAllowed")
          if is_allowed == "true" then
            allowed = true
          end
        end
      end
    end
  end

  if allowed then
    write_json(response_handle, "{\"decision\":true}")
  else
    write_json(response_handle, "{\"decision\":false}")
  end
end
