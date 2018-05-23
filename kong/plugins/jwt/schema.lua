local utils = require "kong.tools.utils"
local iputils = require "resty.iputils"

local function check_user(anonymous)
  if anonymous == "" or utils.is_valid_uuid(anonymous) then
    return true
  end

  return false, "the anonymous user must be empty or a valid uuid"
end

local function validate_ips(v, t, column)
  if v and type(v) == "table" then
    for _, ip in ipairs(v) do
      local _, err = iputils.parse_cidr(ip)
      if type(err) == "string" then -- It's an error only if the second variable is a string
        return false, "cannot parse '" .. ip .. "': " .. err
      end
    end
  end
  return true
end

return {
  no_consumer = true,
  fields = {
    -- uri_param_names = {type = "array", default = {"jwt"}},
    key_claim_name = {type = "string", default = "iss"},
    slat = {type = "string", default = "zQon7#y>[)p=3267"},
    uri_whitelist = {type= "array", default = {}},
    ip_whitelist = {type = "array", func = validate_ips},
    app_key_auth = {type= "table", default = {}},
    secret_is_base64 = {type = "boolean", default = false},
    claims_to_verify = {type = "array", enum = {"exp", "nbf"}},
    anonymous = {type = "string", default = "", func = check_user},
    run_on_preflight = {type = "boolean", default = true},
  },
}
