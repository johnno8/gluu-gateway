local oxd = require "gluu.oxdweb"
local cjson = require("cjson.safe")
local http = require("resty.http")
local r_session = require("resty.session")
local kong_auth_pep_common = require "gluu.kong-auth-pep-common"
local resty_random = require("resty.random")
local resty_string = require("resty.string")

local EXPIRE_DELTA = 10

local function access_token_expires_in(conf, exp)
    local max_id_token_age = conf.max_id_token_age
    return max_id_token_age < exp and max_id_token_age or exp
end


-- here we store discovery info per op_url
local discovery_info_per_op_url = {}

local function ensure_discovery(conf)
    local discovery = discovery_info_per_op_url[conf.op_url]
    if discovery then
        return discovery
    end
    local ptoken = kong_auth_pep_common.get_protection_token(nil, --TODO remove self param
        conf)

    local response, err = oxd.get_discovery(conf.oxd_url,
        { op_host = conf.op_url },
        ptoken)

    if err then
        kong.log.err(err)
        return kong.response.exit(502)
    end

    local status, discovery = response.status, response.body

    if status ~= 200 then
        kong.log.err("get_discovery() responds with status ", status)
        return kong.response.exit(502)
    end

    discovery_info_per_op_url[conf.op_url] = discovery

    return discovery
end

local function combine_uri(uri, params)
    if params == nil or next(params) == nil then
        return uri
    end
    local sep = "?"
    if string.find(uri, "?", 1, true) then
        sep = "&"
    end
    return uri .. sep .. ngx.encode_args(params)
end

local function process_logout(conf, session)
    local session_token = session.data.enc_id_token
    session:destroy()
    local end_session_endpoint = conf.discovery.end_session_endpoint
    if end_session_endpoint then
        local params = {
            id_token_hint = session_token,
            post_logout_redirect_uri = conf.post_logout_redirect_uri
        }

        return ngx.redirect(combine_uri(end_session_endpoint, params))
    end
    if conf.logout_pass_upstream then
        return -- access granted
    end
    ngx.header.content_type = "text/html"
    ngx.say("<html><body>Logged Out</body></html>")
    ngx.exit(ngx.OK)
end

local function validate_id_token(conf, id_token, nonce)

    local discovery = ensure_discovery(conf)

    -- check issuer
    if discovery.issuer ~= id_token.iss then
        kong.log.warn("issuer \"", id_token.iss,
            "\" in id_token is not equal to the issuer from the discovery document \"", discovery.issuer, "\"")
        return false
    end

    -- check sub
    if not id_token.sub then
        kong.log.warn("no \"sub\" claim found in id_token")
        return false
    end

    -- check nonce
    if nonce and nonce ~= id_token.nonce then
        kong.log.warn("nonce \"", id_token.nonce, "\" in id_token is not equal to the nonce that was sent in the request \"", nonce, "\"")
        return false
    end

    -- check issued-at timestamp
    local iat = id_token.iat
    if not iat then
        kong.log.warn("no \"iat\" claim found in id_token")
        return false
    end

    local now = ngx.time()
    if iat > now + EXPIRE_DELTA then
        kong.log.warn("id_token not yet valid: id_token.iat=", iat, ", ngx.time()=", now, ", EXPIRE_DELTA=", EXPIRE_DELTA)
        return false
    end

    -- check expiry timestamp
    local exp = id_token.exp
    if not exp then
        kong.log.warn("no \"exp\" claim found in id_token")
        return false
    end

    if exp + EXPIRE_DELTA < now then
        kong.log.warn("token expired: id_token.exp=", exp, ", ngx.time()=", now)
        return false
    end

    -- check audience (array or string)
    local aud = id_token.aud
    if not aud then
        kong.log.warn("no \"aud\" claim found in id_token")
        return false
    end

    local aud_type = type(aud)
    if aud_type == "table" then
        for _, value in pairs(aud) do
            if value == conf.client_id then
                return true
            end
        end
        kong.log.warn("no match found token audience array: client_id=", conf.client_id)
        return false
    end
    if aud_type == "string" then
        if id_token.aud == conf.client_id then
            return true
        end
        kong.log.warn("token audience does not match: id_token.aud=", id_token.aud, ", client_id=", conf.client_id)
        return false
    end

    kong.log.warn("audience bad type: ", aud_type)
    return false
end

-- Load and validate id token from the id_token properties of the token endpoint response
-- Parameters :
--     - conf the plugin conf
--     - jwt_id_token the id_token from the id_token properties of the token endpoint response
--     - session the current session
-- Return the id_token if valid
-- Return nil, HTTP response status, the error if invalid
--
local function load_and_validate_jwt_id_token(self, conf, jwt_id_token, session)

    local jwt_obj = jwt:load_jwt(jwt_id_token)
    if not jwt_obj.valid then
        return nil, 400, "malformed JWT"
    end

    local id_token, status, err = process_jwt(self, conf, jwt_obj)
    if not jwt_payload then
        return nil, status, err
    end

    kong.log.inspect(jwt_obj.header)
    kong.log.inspect(id_token)

    -- validate the id_token contents
    if not validate_id_token(conf, id_token, session.data.nonce) then
        return nil, 400, "id_token validation failed"
    end

    return id_token
end

-- handle a "code" authorization response from the OP
local function authorization_response(self, conf, session)
    local args = ngx.req.get_uri_args()

    local code, state = args.code, args.state
    if not code or not state then
        kong.log.warn("missed code or state argument(s)")
        return kong.response.exit(400)
    end

    -- check that the state returned in the response against the session; prevents CSRF
    if state ~= session.data.state then
        kong.log.warn("state from argument: ", state, " does not match state restored from session: ", session.data.state)
        return kong.response.exit(400)
    end

    local discovery = ensure_discovery(conf)

    -- check the iss if returned from the OP
    local iss = args.iss
    if iss and iss ~= discovery.issuer then
        kong.log.warn("iss from argument: ", iss, " does not match expected issuer: ", discovery.issuer)
        return kong.response.exit(400)
    end

    -- check the client_id if returned from the OP
    local client_id = args.client_id
    if client_id and client_id ~= conf.client_id then
        kong.log.warn("client_id from argument: ", client_id, " does not match expected client_id: ", conf.client_id)
        return kong.response.exit(400)
    end

    kong.log.debug("Authentication with OP done -> Calling OP Token Endpoint to obtain tokens")

    local ptoken = kong_auth_pep_common.get_protection_token(self, conf)

    local response, err = oxd.get_tokens_by_code(conf.oxd_url,
        {
            oxd_id = conf.oxd_id,
            code = args.code,
            state = session.data.state,
        },
        ptoken)

    if err then
        kong.log.err(err)
        return kong.response.exit(502)
    end

    local status, json = response.status, response.body

    if status ~= 200 then
        kong.log.err("get_tokens_by_code() responds with status ", status)
        return kong.response.exit(502)
    end


    local id_token, status, err = load_and_validate_jwt_id_token(self, conf, json.id_token, session);
    if err then
        kong.log.err(err)
        return kong.response.exit(status)
    end


    local session_data = session.data
    -- clear state and nonce to protect against potential misuse
    session_data.nonce = nil
    session_data.state = nil

    session_data.enc_id_token = json.id_token
    session_data.id_token = id_token

    session_data.access_token = json.access_token
    session_data.access_token_expiration = ngx.time() + access_token_expires_in(conf, json.expires_in)
    session_data.refresh_token = json.refresh_token

    local ptoken = kong_auth_pep_common.get_protection_token(self, conf)

    local response, err = oxd.get_user_info(conf.oxd_url,
        {
            oxd_id = conf.oxd_id,
            access_token = access_token,
        },
        ptoken)

    if err then
        kong.log.err(err)
        return kong.response.exit(502)
    end

    local status, userinfo = response.status, response.body

    if status ~= 200 then
        kong.log.err("get_user_info() responds with status ", status)
        return kong.response.exit(502)
    end

    if id_token.sub ~= userinfo.sub then
        kong.log.warn("\"sub\" claim in id_token (\"", id_token.sub, "\") is not equal to the \"sub\" claim returned from the userinfo endpoint (\"" .. (user.sub or "null") .. "\")"
        return kong.response.exit(502)
    end

    session.data.user = userinfo

    session:save()

    -- redirect to the URL that was accessed originally
    kong.log.debug("OIDC Authorization Code Flow completed -> Redirecting to original URL (", session.data.original_url, ")")
    ngx.redirect(session.data.original_url)
end

local function refresh_access_token(self, conf, session)

    local current_time = ngx.time()
    if current_time < session.data.access_token_expiration then
        return session.data.access_token
    end

    if not session.data.refresh_token then
        kong.log.debug("token expired and no refresh token available")
        return
    end

    kong.log.debug("refreshing expired access_token: ", session.data.access_token, " with: ", session.data.refresh_token)

    local ptoken = kong_auth_pep_common.get_protection_token(nil, conf)

    local response, err = oxd.get_access_token_by_refresh_token(conf.oxd_url,
        {
            oxd_id = conf.oxd_id,
            refresh_token = session.data.refresh_token,
        },
        ptoken)

    if err then
        kong.log.err(err)
        return kong.response.exit(502)
    end

    local status, json = response.status, response.body

    if status ~= 200 then
        kong.log.err("get_access_token_by_refresh_token() responds with status ", status)
        return kong.response.exit(502)
    end

    local id_token, status, err = load_and_validate_jwt_id_token(self, conf, json.id_token, session);
    if err then
        kong.log.err(err)
        return kong.response.exit(status)
    end

    kong.log.debug("access_token refreshed: ", json.access_token, " updated refresh_token: ", json.refresh_token)

    session.data.access_token = json.access_token
    session.data.access_token_expiration = current_time + access_token_expires_in(conf, json.expires_in)
    session.data.refresh_token = json.refresh_token

    session.data.enc_id_token = json.id_token
    session.data.id_token = id_token

    -- save the session with the new access_token and optionally the new refresh_token and id_token
    session:save()

    return session.data.access_token
end

-- send the browser of to the OP's authorization endpoint
local function authorize(conf, session, prompt)

    -- generate state and nonce
    local state = resty_string.to_hex(resty_random.bytes(16))
    local nonce = resty_string.to_hex(resty_random.bytes(16))

    -- assemble the parameters to the authentication request
    local params = {
        client_id = conf.client_id,
        response_type = "code",
        scope = conf.requested_scopes,
        redirect_uri = conf.authorization_redirect_uri,
        state = state,
        nonce = nonce,
        -- TODO display =
    }

    -- store state in the session
    local session_data = session.data
    --session.data.original_url = target_url
    session_data.state = state
    session_data.nonce = nonce
    params.prompt = prompt
    session_data.original_url = target_url -- TODO
    session:save()

    -- redirect to the /authorization endpoint
    ngx.header["Cache-Control"] = "no-cache, no-store, max-age=0"
    ngx.redirect(combine_uri(conf.discovery.authorization_endpoint, params))
end


return function(self, conf)
    local err

    local session = r_session.start()
    local session_data = session.data

    -- see if this is a request to the redirect_uri i.e. an authorization response
    local path = ngx.var.uri
    if path == conf.authorization_redirect_path then
        kong.log.debug("Redirect URI path (", path, ") is currently navigated -> Processing authorization response coming from OP")

        if not session.present then
            kong.log.err("request to the authorization response path but there's no session state found")
            return kong.response.exit(400)
        end

        return authorization_response(self, conf, session)
    end

    -- see is this a request to logout
    if path == conf.logout_path then
        kong.log.debug("Logout path (", path, ") is currently navigated -> Processing local session removal before redirecting to next step of logout process")

        if not session.present then
            kong.log.warn("request to the logout path but there's no session state found")
            return kong.response.exit(400)
        end

        return process_logout(conf, session)
    end

    local token_expired = false
    if session.present and session_data.id_token then
        -- refresh access_token if necessary
        if not refresh_access_token(self, conf, session) then
            token_expired = true
        end
    end

    kong.log.debug(
        "session.present=", session.present,
        ", session.data.id_token=", session_data.id_token ~= nil,
        ", token_expired=", token_expired)

    if not session.present
            or not session_data.id_token
            or token_expired
            or (session_data.id_token.auth_time and (session_data.id_token.auth_time + conf.max_id_token_auth_age) < ngx.time()) then
        kong.log.debug("Authentication is required - Redirecting to OP Authorization endpoint")
        return authorize(conf, session)
    end

    if (session_data.id_token.iat + conf.max_id_token_auth_age) < ngx.time() or
            session_data.id_token.exp < ngx.time() then
        kong.log.debug("Silent authentication is required - Redirecting to OP Authorization endpoint")
        return authorize(conf, session, "none")
    end

    -- TODO save contex, set headers
end


