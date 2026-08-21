local _M = {}
local jwt = require 'resty.jwt'
local openssl_pkey = require 'resty.openssl.pkey'
local cjson = require 'cjson.safe'
local sha256 = require 'resty.sha256'
local random = require 'resty.random'
local redis = require 'resty.redis'

--
-- Use an error lookup table
--
local errors = {
    invalid_token = {
        status = ngx.HTTP_UNAUTHORIZED,
        message = 'Missing, invalid or expired access token'
    },
    invalid_dpop_proof = {
        status = ngx.HTTP_UNAUTHORIZED,
        message = 'Missing, invalid or expired DPoP proof JWT'
    },
    use_dpop_nonce = {
        status = ngx.HTTP_UNAUTHORIZED,
        message = 'Use the provided DPoP nonce'
    },
    server_error = {
        status = ngx.HTTP_INTERNAL_SERVER_ERROR,
        message = 'Problem encountered processing the request'
    }
}

--
-- Return an error response based on the error code
--
local function error_response(code, server_issued_nonce)

    local error = errors[code]
    if not error then
        error = errors['server_error']
    end
    
    ngx.status = error.status
    ngx.header['content-type'] = 'application/json'
    if error.status == ngx.HTTP_UNAUTHORIZED then

        ngx.header['WWW-Authenticate'] = string.format('DPoP error="%s", error_description="%s"', code, error.message)

        if code == 'use_dpop_nonce' and server_issued_nonce then
            ngx.header['DPoP-Nonce'] = server_issued_nonce
            ngx.header['Cache-Control'] = 'no-store'
        end
    end
    
    local method = ngx.req.get_method():upper()
    if method ~= 'HEAD' then
        local jsonData = '{"code":"' .. code .. '","message":"' .. error.message .. '"}'
        ngx.say(jsonData)
    end
    
    ngx.exit(error.status)
end

--
-- A utility to extend base64 to base64 url encoding
--
local function base64url_encode(bytes)
    return ngx.encode_base64(bytes):gsub("%+", "-"):gsub("/", "_"):gsub("=", "")
end

--
-- A utility to get a hash for comparison
--
local function base64url_encoded_sha256_hash(text)
    local digest = sha256:new()
    digest:update(text)
    local bytes = digest:final()
    return base64url_encode(bytes)
end

--
-- Validate that the access token jwt claim matches the DPoP public key thumbprint
-- Also validate that the hash of the opaque access token matches the DPoP proof's ath claim
--
local function validate_access_token(access_token_jwt, dpop_jwk, ath_claim)

    local invalid_token = 'invalid_token'

    local jwt_obj = jwt:load_jwt(access_token_jwt)
    if not jwt_obj or not jwt_obj.valid then
        return nil, invalid_token, 'Access token JWT is malformed'
    end

    if not jwt_obj.payload.cnf or not jwt_obj.payload.cnf['jkt'] then
        return nil, invalid_token, 'Access token JWT is not DPoP bound'
    end
    local jkt_claim = jwt_obj.payload.cnf['jkt']

    -- Use the canoncial form from RFC 7638
    local jwk_json =
        '{"crv":' .. cjson.encode(dpop_jwk.crv) ..
        ',"kty":' .. cjson.encode(dpop_jwk.kty) ..
        ',"x":'   .. cjson.encode(dpop_jwk.x) ..
        ',"y":'   .. cjson.encode(dpop_jwk.y) ..
        '}'

    local jwk_thumbprint = base64url_encoded_sha256_hash(jwk_json)
    if jkt_claim ~= jwk_thumbprint then
        return nil, invalid_token, 'Access token jtk claim does not match the DPoP public key thumbprint'
    end

    -- Use the original access token in phantom token flows, which NGINX stores in request state
    local access_token_for_hash_verification = ngx.var.original_access_token or access_token_jwt

    local at_hash = base64url_encoded_sha256_hash(access_token_for_hash_verification)
    if ath_claim ~= at_hash then
        return nil, invalid_token, 'The ath claim of the DPoP proof JWT does not match the hash of the client access token'
    end

    return true
end

--
-- Tne entry point to validate token details
--
local function validate(access_token_jwt, dpop_proof_jwt)

    local invalid_dpop_proof = 'invalid_dpop_proof'

    local jwt_obj = jwt:load_jwt(dpop_proof_jwt)
    if not jwt_obj or not jwt_obj.valid then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT is malformed'
    end

    if not jwt_obj.header then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has a missing JWT header'
    end

    if jwt_obj.header.alg ~= 'ES256' then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has an unsupported alg value'
    end

    if jwt_obj.header.typ ~= 'dpop+jwt' then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has an invalid typ value'
    end

    if not jwt_obj.header.jwk then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has no jwk'
    end

    if jwt_obj.header.jwk.kty ~= 'EC' then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT jwk is not an EC key'
    end

    if jwt_obj.header.jwk.crv ~= 'P-256' then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT jwk is not a P-256 key'
    end

    if not jwt_obj.header.jwk.x or not jwt_obj.header.jwk.y then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT jwk does not have x and y parameters'
    end

    local jwk_json_string, err1 = cjson.encode({
        crv = jwt_obj.header.jwk.crv,
        kty = jwt_obj.header.jwk.kty,
        x = jwt_obj.header.jwk.x,
        y = jwt_obj.header.jwk.y,
    })
    if not jwk_json_string then
        return nil, invalid_dpop_proof, 'Could not encode JWK: ' .. tostring(err1)
    end

    local public_key, err2 = openssl_pkey.new(jwk_json_string, {
        format = 'JWK'
    })
    if not public_key then
        return nil, invalid_dpop_proof, 'Could not import DPoP public key: ' .. tostring(err2)
    end

    local public_key_pem, err3 = public_key:to_PEM('public')
    if not public_key_pem then
        return nil, invalid_dpop_proof, 'Could not export public key: ' .. tostring(err3)
    end

    local response = jwt:verify_jwt_obj(public_key_pem, jwt_obj)
    if not response.verified then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT failed validation: ' .. tostring(response.reason)
    end
    local claims = response.payload

    if not claims.jti then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has a missing jti claim'
    end

    if not claims.ath then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has a missing ath claim'
    end

    local expected_htm = ngx.req.get_method()
    if not claims.htm or claims.htm ~= expected_htm then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has an invalid htm claim'
    end

    local host = ngx.var.http_host or ngx.var.server_name
    local expected_htu = ngx.var.scheme .. "://" .. host .. ngx.var.uri
    if not claims.htu or claims.htu ~= expected_htu then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has an invalid htu claim'
    end

    if not claims.iat then
        return nil, invalid_dpop_proof, 'DPoP Proof JWT has a missing iat claim'
    end

    local ok, error_code, error_reason = validate_access_token(access_token_jwt, jwt_obj.header.jwk, claims.ath)
    if not ok then 
        return nil, error_code, error_reason
    end

    return claims, nil, nil
end

--
-- Handle the states of cache lookup
--
local function get_cache_item(type, key, cache)

    if not key then
        return nil, nil
    end

    local value, err = cache:get(type .. ' : ' .. key)
    if err then
        return nil, 'Error getting ' .. type .. ' cache item: ' .. err
    elseif value == ngx.null then
        return nil, nil
    else
        return value, nil
    end
end

--
-- Handle setting a cache item with a time to live
--
local function set_cache_item(type, key, ttlSeconds, cache)

    local ok, err = cache:set(type .. ' : ' .. key, 'true', 'EX', ttlSeconds)
    if not ok then
        return false, 'server_error', 'Unable to save ' .. type .. ' cache item: ' .. err
    end
    
    return true, nil
end

--
-- Validate the incoming nonce by finding it in the cache, or issue a challenge if not found
--
local function validate_nonce(nonceClaim, cache, config)

    local value, find_err = get_cache_item('nonce', nonceClaim, cache)
    if find_err then
        return false, 'server_error', find_err
    end

    if value then
        return true, nil, nil
    end

    local bytes = random.bytes(32)
    local server_issued_nonce = ngx.encode_base64(bytes):gsub("%+", "-"):gsub("/", "_"):gsub("=", "")

    local set_ok, set_err = set_cache_item('nonce', server_issued_nonce, config.time_to_live_seconds, cache)
    if not set_ok then
        return false, 'server_error', set_err
    end
    
    error_response('use_dpop_nonce', server_issued_nonce)
end

--
-- Validate the incoming jti by returning an error if it is found it in the cache
--
local function validate_jti(jtiClaim, cache, config)

    local value, find_err = get_cache_item('jti', jtiClaim, cache)
    if find_err then
        return false, 'server_error', find_err
    end

    if value then
        return false, 'invalid_dpop_proof', 'A DPoP proof was received with a jti claim that exists in the cache'
    end

    local set_ok, set_err = set_cache_item('jti', jtiClaim, config.time_to_live_seconds, cache)
    if not set_ok then
        return false, 'server_error', set_err
    end

    return true, nil, nil
end

--
-- Apply default configuration settings
--
local function apply_default_configuration(config)

    if config.time_to_live_seconds == nil or config.time_to_live_seconds <= 0 then
        config.time_to_live_seconds = 300
    end
end

--
-- Validate incorrect configuration before running in OpenResty
--
function _M.validate(config)

    if not config then
        return nil, 'The DPoP sender constrained token plugin requires configuration'
    end

    if not config.cache_server then
        return nil, 'The DPoP sender constrained token plugin requires a cache_server parameter'
    end

    if not config.cache_port or config.cache_port <= 0 then
        return nil, 'The DPoP sender constrained token plugin requires a cache_port parameter'
    end

    return true
end

--
-- The entry point for DPoP processing
--
function _M.run(config)

    local ok, err, error_code, error_reason

    if ngx.req.get_method() == 'OPTIONS' then
        return
    end

    apply_default_configuration(config)

    -- Get the JWT access token from the Authorization: DPoP header
    local auth_header = ngx.req.get_headers()['Authorization']
    if not auth_header then
        error_response('invalid_token')
    end
    local access_token_jwt = auth_header:match("^%s*[Dd][Pp][Oo][Pp]%s+(.+)%s*$")
    if not access_token_jwt then
        error_response('invalid_token')
    end

    -- Get the DPoP proof JWT from the DPoP header
    local dpop_proof_jwt = ngx.req.get_headers()['DPoP']
    if not dpop_proof_jwt then
        error_response('invalid_dpop_proof')
    end

    -- Do the main token validation
    local dpop_claims
    dpop_claims, error_code, error_reason = validate(access_token_jwt, dpop_proof_jwt)
    if error_code then
        ngx.log(ngx.WARN, error_reason)
        error_response(error_code)
    end

    -- Connect to the cache
    local cache = redis:new()
    ok, err = cache:connect(config.cache_server, config.cache_port)
    if not ok then
        ngx.log(ngx.WARN, 'Cache connection failure: ', err)
        error_response('server_error')
    end

    -- Validate the nonce claim to ensure that the DPoP proof is fresh
    local ok, error_code, error_reason = validate_nonce(dpop_claims.nonce, cache, config)
    if error_code then
        ngx.log(ngx.WARN, error_reason)
        error_response(error_code)
    end

    -- Validate the jti claim to prevent replay of the same DPoP proof
    local ok, error_code, error_reason = validate_jti(dpop_claims.jti, cache, config)
    if error_code then
        ngx.log(ngx.WARN, error_reason)
        error_response(error_code)
    end

    -- In this example deployment, the target API treats the access token as a bearer token
    ngx.req.set_header('Authorization', 'Bearer ' .. access_token_jwt)
end

return _M
