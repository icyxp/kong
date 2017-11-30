local singletons = require "kong.singletons"
local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local string_format = string.format
local ngx_re_gmatch = ngx.re.gmatch

local ngx_set_header = ngx.req.set_header
local get_method = ngx.req.get_method

local resty_sha1 = require "resty.sha1"
local resty_md5 = require "resty.md5"
local str = require "resty.string"

local JwtHandler = BasePlugin:extend()

JwtHandler.PRIORITY = 1005
JwtHandler.VERSION = "0.1.0"

local function mapping_jwt(authorization)
  if authorization then
    local iterator, iter_err = ngx_re_gmatch(authorization, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(request)
--  local uri_parameters = request.get_uri_args()
--
--  for _, v in ipairs(conf.uri_param_names) do
--    if uri_parameters[v] then
--      return uri_parameters[v]
--    end
--  end

  local jwt_key = "authorization"
  local authorization

  authorization = ngx.unescape_uri(ngx.var["cookie_" .. jwt_key])
  if authorization == "" then
    authorization = request.get_headers()[jwt_key]
  end

  local token, err1 = mapping_jwt(authorization)
  if err1 then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err1)
  end

  local app_key = request.get_headers()['x-app-key']

  return token, app_key
end

function JwtHandler:new()
  JwtHandler.super.new(self, "jwt")
end

string.split = function(s, p)
  local rt= {}
  string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
  return rt
end

local function uri_authentication(uri_list, request, conf, claims)
  -- domestic consumer uri authentication
  local method = ngx.var.request_method
  local sha1 = resty_sha1:new()
  local md5 = resty_md5:new()
  local len = #uri_list

  -- md5(user_id + tenant_id + slat + jwt sign time)
  md5:update(claims.extra.user_id .. claims.extra.tenant_id .. conf.slat .. claims.iat)
  local digest = md5:final()
  local key = str.to_hex(digest)

  -- remove dynamic uri parameter [4,6], trap in here!!
  table.remove(uri_list, 6)
  table.remove(uri_list, 4)

  -- add method + len + md5
  table.insert(uri_list, method)
  table.insert(uri_list, len)
  table.insert(uri_list, key)

  -- make uri token
  local uri_merge = table.concat(uri_list)
  sha1:update(uri_merge)
  local digest2 = sha1:final()
  local sign_token = str.to_hex(digest2)

  --diff uri token
  local api_token = request.get_headers()["x-api-token"]
  if api_token == nil then
    local args = ngx.req.get_uri_args()
    api_token = args.api_token
  end
  if sign_token ~= api_token then
    return 403
  end
end

local function extended_vailidation(request, conf, jwt_claims, app_key_claims)

  local claims
  local verify_ip
  if (jwt_claims and app_key_claims) ~= nil then
    claims = app_key_claims
    verify_ip = true
  elseif jwt_claims ~= nil then
    claims = jwt_claims
    verify_ip = false
  else
    claims = app_key_claims
    verify_ip = true
  end

  local iat = claims.iat
  local exp = claims.exp

  -- Verify jwt is expired
  if (iat and exp) == nil then
    return {status = 401, message = "iat or exp time can't empty"}
  end

  if exp <= iat then
    return {status = 401, message = "token expired"}
  end

  -- Verify ip addr
  if verify_ip == true then
    local current_remote_addr = ngx.var.remote_addr
    local ip_decimal = 0
    local postion = 3
    for i in string.gmatch(current_remote_addr, [[%d+]]) do
      ip_decimal = ip_decimal + math.pow(256, postion) * i
      postion = postion - 1
    end

    if (ip_decimal >= 0x7f000000 and ip_decimal <= 0x7fffffff) or -- 127.0.0.0 ~ 127.255.255.255
            (ip_decimal >= 0x0a000000 and ip_decimal <= 0x0affffff) or -- 10.0.0.0 ~ 10.255.255.255
            (ip_decimal >= 0xac100000 and ip_decimal <= 0xac1fffff) or -- 172.16.0.0 ~ 172.31.255.255
            (ip_decimal >= 0xc0a80000 and ip_decimal <= 0xc0a8ffff) then   -- 192.168.0.0 ~ 192.168.255.255
    else
      return {status = 403, message = "app_token only intranet is allowed"}
    end
  end

  local authentication
  -- Verify user type
  if claims.client_type == 1 then
    authentication = true
  else
    return nil
  end

  -- Verfiy uri prefix
  local uri_list = string.split(ngx.var.uri, '/')
  if ngx.re.match(uri_list[1], "inno-") and (uri_list[1] ~= "inno-static") then
    authentication = true
  else
    return nil
  end

  if authentication == true then
    local code = uri_authentication(uri_list, request, conf, claims)
    if code ~= nil then
      return {status = code, message = "invalid api token"}
    end
  end
end

local function load_credential(jwt_secret_key)
  local rows, err = singletons.dao.jwt_secrets:find_all {key = jwt_secret_key}
  if err then
    return nil, err
  end
  return rows[1]
end

local function load_consumer(consumer_id, anonymous)
  local result, err = singletons.dao.consumers:find { id = consumer_id }
  if not result then
    if anonymous and not err then
      err = 'anonymous consumer "' .. consumer_id .. '" not found'
    end
    return nil, err
  end
  return result
end

local function set_consumer(consumer, jwt_secret, claims, jwt_token, app_key_token)
  ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)

  if jwt_token ~= nil then
    ngx_set_header(constants.HEADERS.AUTHORIZATION, "Bearer " .. jwt_token)
  end
  if app_key_token ~= nil then
    ngx_set_header(constants.HEADERS.APP_KEY, app_key_token)
  end

  if (claims.extra ~= nil) and (next(claims.extra) ~= nil) then
    ngx_set_header(constants.HEADERS.CONSUMER_USER_ID, claims.extra.user_id)
    ngx_set_header(constants.HEADERS.CONSUMER_TENANT_ID, claims.extra.tenant_id)
  end

  ngx.ctx.authenticated_consumer = consumer
  if jwt_secret then
    ngx.ctx.authenticated_credential = jwt_secret
    ngx_set_header(constants.HEADERS.ANONYMOUS, nil) -- in case of auth plugins concatenation
  else
    ngx_set_header(constants.HEADERS.ANONYMOUS, true)
  end

end

local function decode_jwt(token, conf)
  local ttype = type(token)
  if ttype ~= "string" then
    if ttype == "nil" then
      return false, {status = 401}
    elseif ttype == "table" then
      return false, {status = 401, message = "Multiple tokens provided"}
    else
      return false, {status = 401, message = "Unrecognizable token"}
    end
  end

  -- Decode token to find out who the consumer is
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, {status = 401, message = "Bad token; " .. tostring(err)}
  end

  local claims = jwt.claims

  local jwt_secret_key = claims[conf.key_claim_name]
  if not jwt_secret_key then
    return false, {status = 401, message = "No mandatory '" .. conf.key_claim_name .. "' in claims"}
  end

  -- Retrieve the secret
  local jwt_secret_cache_key = singletons.dao.jwt_secrets:cache_key(jwt_secret_key)
  local jwt_secret, err      = singletons.cache:get(jwt_secret_cache_key, nil,
                                                    load_credential, jwt_secret_key)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  if not jwt_secret then
    return false, {status = 401, message = "No credentials found for given '" .. conf.key_claim_name .. "'"}
  end

  local algorithm = jwt_secret.algorithm or "HS256"

  -- Verify "alg"
  if jwt.header.alg ~= algorithm then
    return false, {status = 401, message = "Invalid algorithm"}
  end

  local jwt_secret_value = algorithm == "HS256" and jwt_secret.secret or jwt_secret.rsa_public_key
  if conf.secret_is_base64 then
    jwt_secret_value = jwt:b64_decode(jwt_secret_value)
  end

  if not jwt_secret_value then
    return false, {status = 401, message = "Invalid key/secret"}
  end

  -- Now verify the JWT signature
  if not jwt:verify_signature(jwt_secret_value) then
    return false, {status = 401, message = "Invalid signature"}
  end

  -- Verify the JWT registered claims
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    return false, {status = 401, message = errors}
  end

  -- Retrieve the consumer
  local consumer_cache_key = singletons.dao.consumers:cache_key(jwt_secret.consumer_id)
  local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                  load_consumer,
                                                  jwt_secret.consumer_id, true)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  -- However this should not happen
  if not consumer then
    return false, {status = 401, message = string_format("Could not find consumer for '%s=%s'", conf.key_claim_name, jwt_secret_key)}
  end

  return true, {consumer = consumer, jwt_secret = jwt_secret, claims = claims}
end

local function do_authentication(conf)
  local token, app_key = retrieve_token(ngx.req)

  -- decode & vailidate jwt
  local ok, ok2 = true, true
  local token_data, app_key_data
  if (token or app_key) == nil then
    return false, {status = 401 }
  elseif (token and app_key) ~= nil then
    ok, token_data = decode_jwt(token, conf)
    ok2, app_key_data = decode_jwt(app_key, conf)
  elseif token ~= nil then
    ok, token_data = decode_jwt(token, conf)
  else
    ok2, app_key_data = decode_jwt(app_key, conf)
  end

  -- check err
  if not ok then
    return false, token_data
  elseif not ok2 then
    return false, app_key_data
  end

  -- add extended vailidation
  local err
  if (token_data and app_key_data) ~= nil then
    err = extended_vailidation(ngx.req, conf, token_data.claims, app_key_data.claims)
  elseif token_data ~= nil then
    err = extended_vailidation(ngx.req, conf, token_data.claims, nil)
  else
    err = extended_vailidation(ngx.req, conf, nil, app_key_data.claims)
  end

  -- check extended err
  if err then
    return false, err
  end

  -- set consumer
  if (token_data and app_key_data) ~= nil then
    set_consumer(token_data.consumer, token_data.jwt_secret, token_data.claims, token, app_key)
  elseif token_data ~= nil then
    set_consumer(token_data.consumer, token_data.jwt_secret, token_data.claims, token, nil)
  else
    set_consumer(app_key_data.consumer, app_key_data.jwt_secret, app_key_data.claims, nil, app_key)
  end

  return true
end

function JwtHandler:access(conf)
  JwtHandler.super.access(self)

  -- add uri whitelist by icyboy
  local method = ngx.var.request_method
  local uri = ngx.var.uri
  for _, v in ipairs(conf.uri_whitelist) do
    if (v.method == method) and (v.uri == uri) then
      return
    end
  end

  -- check if preflight request and whether it should be authenticated
  if conf.run_on_preflight == false and get_method() == "OPTIONS" then
    -- FIXME: the above `== false` test is because existing entries in the db will
    -- have `nil` and hence will by default start passing the preflight request
    -- This should be fixed by a migration to update the actual entries
    -- in the datastore
    return
  end

  if ngx.ctx.authenticated_credential and conf.anonymous ~= "" then
    -- we're already authenticated, and we're configured for using anonymous,
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
    if conf.anonymous ~= "" then
      -- get anonymous user
      local consumer_cache_key = singletons.dao.consumers:cache_key(conf.anonymous)
      local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
                                                      load_consumer,
                                                      conf.anonymous, true)
      if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      end
      set_consumer(consumer, nil, nil, nil)
    else
      return responses.send(err.status, err.message)
    end
  end
end

return JwtHandler
