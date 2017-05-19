local utils = require "kong.tools.utils"

local function check_user(anonymous)
  if anonymous == "" or utils.is_valid_uuid(anonymous) then
    return true
  end
  
  return false, "the anonymous user must be empty or a valid uuid"
end

return {
  no_consumer = true,
  fields = {
    -- uri_param_names = {type = "array", default = {"jwt"}},
    key_claim_name = {type = "string", default = "iss"},
    slat = {type = "string", default = "zQon7#y>[)p=3267"},
    uri_whitelist = {type= "array", default = {{method="POST", uri="/inno-user/user/v1/user/identify"}, {method="POST", uri="/inno-user/user/v1/user/sign_jwt"}, {method="POST", uri="/inno-user/user/users/identify"}, {method="POST", uri="/inno-user/user/users/sign_jwt"}}},
    secret_is_base64 = {type = "boolean", default = false},
    claims_to_verify = {type = "array", enum = {"exp", "nbf"}},
    anonymous = {type = "string", default = "", func = check_user},
  }
}
