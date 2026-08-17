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

local function parse_top_level_array(text)
  local i = skip_ws(text, 1)
  if string.sub(text, i, i) ~= "[" then
    return nil
  end

  i = i + 1
  local items = {}

  while true do
    i = skip_ws(text, i)
    if i > #text then
      return nil
    end

    local ch = string.sub(text, i, i)
    if ch == "]" then
      return items
    end

    local ending = nil
    if ch == "{" then
      ending = scan_composite(text, i, "{", "}")
    elseif ch == "[" then
      ending = scan_composite(text, i, "[", "]")
    elseif ch == "\"" then
      ending = scan_string(text, i)
    else
      ending = scan_primitive(text, i)
    end

    if ending == nil then
      return nil
    end

    items[#items + 1] = string.sub(text, i, ending)
    i = skip_ws(text, ending + 1)
    if i > #text then
      return nil
    end

    ch = string.sub(text, i, i)
    if ch == "," then
      i = i + 1
    elseif ch == "]" then
      return items
    else
      return nil
    end
  end
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

-- Extract the unquoted string content from a quoted JSON string value.
local function unquote_json_string(field_json)
  if field_json == nil then
    return ""
  end
  local s = trim_ws(field_json)
  if #s >= 2 and string.sub(s, 1, 1) == "\"" and string.sub(s, -1) == "\"" then
    -- Basic JSON string unescaping for common cases.
    local inner = string.sub(s, 2, -2)
    inner = string.gsub(inner, "\\\"", "\"")
    inner = string.gsub(inner, "\\\\", "\\")
    inner = string.gsub(inner, "\\/", "/")
    inner = string.gsub(inner, "\\n", "\n")
    inner = string.gsub(inner, "\\r", "\r")
    inner = string.gsub(inner, "\\t", "\t")
    return inner
  end
  return s
end

-- Encode a Lua string array as a JSON array of quoted strings.
local function encode_string_array(arr)
  local parts = {}
  for i, v in ipairs(arr) do
    parts[i] = json_quote(v)
  end
  return "[" .. table.concat(parts, ",") .. "]"
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

  local items = parse_top_level_array(raw_body)
  if items == nil then
    write_request_error(request_handle, 400, "bad request")
    return
  end

  for _, item in ipairs(items) do
    if missing_required_string_field(item, "type") then
      write_request_error(request_handle, 400, "Missing required parameter: type")
      return
    end
    if missing_required_string_field(item, "operation") then
      write_request_error(request_handle, 400, "Missing required parameter: operation")
      return
    end
  end

  -- Row-16 (Validation) parity: the legacy CheckRequestValidator
  -- (CheckRequestValidator.java:76-94) raises NotUniqueResourcesIdsException
  -- when two bulk entries share the same `id`; the server returns HTTP 400
  -- with a message naming the duplicate id. Envoy Lua replicates the check
  -- here so the request never reaches OPA. Entries without an `id` field
  -- are allowed (they carry no duplicate risk in the legacy bulk contract).
  do
    local seen = {}
    for _, item in ipairs(items) do
      local id_json = extract_field_json(item, "id")
      if id_json ~= nil then
        local id_value = trim_ws(id_json)
        if id_value ~= "" and id_value ~= "null" then
          if seen[id_value] then
            write_request_error(
              request_handle,
              400,
              "Duplicate resource id in bulk request: resource ids must be unique"
            )
            return
          end
          seen[id_value] = true
        end
      end
    end
  end

  -- Build canonical resources array and collect legacy IDs for response mapping.
  local resource_parts = {}
  local legacy_ids = {}
  for i, item in ipairs(items) do
    local type_json = extract_field_json(item, "type")
    local op_json = extract_field_json(item, "operation")
    local res_json = extract_field_json(item, "resource")
    local id_json = extract_field_json(item, "id")

    if type_json == nil then type_json = "\"\"" end
    if op_json == nil then op_json = "\"\"" end
    if res_json == nil then res_json = "{}" end

    resource_parts[i] = "{\"resourceType\":"
      .. type_json
      .. ",\"operation\":"
      .. op_json
      .. ",\"resource\":"
      .. res_json
      .. "}"

    -- Preserve legacy id for response remapping.
    legacy_ids[i] = unquote_json_string(id_json)
  end

  local resources_json = "[" .. table.concat(resource_parts, ",") .. "]"

  -- Store legacy ids in stream metadata for the response phase.
  request_handle:streamInfo():dynamicMetadata():set(
    "envoy.filters.http.lua",
    "bulk_ids",
    encode_string_array(legacy_ids)
  )

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
    .. resources_json
    .. "}}"

  rewrite_to_opa(request_handle, payload)
  request_handle:headers():replace("x-authz-original-path", "/access/v1/check/resource/bulk")
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

  -- Retrieve legacy ids stored during request phase.
  local meta = response_handle:streamInfo():dynamicMetadata():get("envoy.filters.http.lua")
  local ids_json = (meta and meta["bulk_ids"]) or "[]"
  local stored_ids = parse_top_level_array(ids_json) or {}

  -- Parse canonical results array from AuthorizeResponse.
  local results_json = extract_field_json(unwrapped, "results")
  local is_allowed_vals = {}
  if results_json ~= nil then
    local result_items = parse_top_level_array(results_json)
    if result_items ~= nil then
      for i, item in ipairs(result_items) do
        local is_allowed_json = extract_field_json(item, "isAllowed")
        is_allowed_vals[i] = trim_ws(is_allowed_json or "")
      end
    end
  end

  -- Build allowed IDs array: include stored_ids[i] for each isAllowed result at index i.
  local allowed = {}
  for i, is_allowed in ipairs(is_allowed_vals) do
    if is_allowed == "true" then
      local raw_id = stored_ids[i]
      if raw_id ~= nil then
        -- raw_id is already a quoted JSON string (e.g. "\"id-1\"")
        local id_trimmed = trim_ws(raw_id)
        -- It may be a quoted string already if stored_ids came from parse_top_level_array
        -- which returns raw JSON token. Check if it's quoted.
        if string.sub(id_trimmed, 1, 1) == "\"" and #id_trimmed >= 2 then
          -- non-empty quoted string check
          local inner = string.sub(id_trimmed, 2, -2)
          if inner ~= "" then
            allowed[#allowed + 1] = id_trimmed
          end
        elseif id_trimmed ~= "" and id_trimmed ~= "null" then
          allowed[#allowed + 1] = json_quote(id_trimmed)
        end
      end
    end
  end

  if #allowed == 0 then
    write_json(response_handle, "[]")
  else
    write_json(response_handle, "[" .. table.concat(allowed, ",") .. "]")
  end
end
