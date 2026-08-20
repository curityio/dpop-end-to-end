local _M = {}
local jwt = require 'resty.jwt'
local openssl_pkey = require 'resty.openssl.pkey'
local cjson = require 'cjson.safe'
local sha256 = require 'resty.sha256'
local random = require 'resty.random'

--
-- Return errors due to invalid tokens or introspection technical problems
--
local function error_response(status, code, message)

    local method = ngx.req.get_method():upper()
    if method ~= 'HEAD' then
    
        ngx.status = status
        ngx.header['content-type'] = 'application/json'
        if status == 401 then
            ngx.header['WWW-Authenticate'] = string.format('DPoP error="%s", error_description="%s"', scheme, code, message)
        end
        
        local jsonData = '{"code":"' .. code .. '","message":"' .. message .. '"}'
        ngx.say(jsonData)
    end
    
    ngx.exit(status)
end

--
-- Issue a server-issued nonce to the client
--
local function nonce_challenge_response()

    local bytes = random.bytes(32)
    local base64Nonce = ngx.encode_base64(bytes):gsub("%+", "-"):gsub("/", "_"):gsub("=", "")

    ngx.header['DPoP-Nonce'] = base64Nonce
    error_response(ngx.HTTP_UNAUTHORIZED, 'use_dpop_nonce', 'use provided DPoP nonce')
end

--
-- A utility to handle special characters
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

    local jwt_obj = jwt:load_jwt(access_token_jwt)
    if not jwt_obj or not jwt_obj.valid then
        return nil, 'Access token JWT is malformed'
    end

    if not jwt_obj.payload.cnf or not jwt_obj.payload.cnf['jkt'] then
        return nil, 'Access token JWT is not DPoP bound'
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
        return nil, 'Access token jtk claim does not match the DPoP public key thumbprint'
    end

    -- Use the original access token in phantom token flows, which NGINX stores in request state
    local access_token_for_hash_verification = ngx.var.original_access_token or access_token_jwt

    local at_hash = base64url_encoded_sha256_hash(access_token_for_hash_verification)
    if ath_claim ~= at_hash then
        return nil, 'The ath claim of the DPoP proof JWT does not match the hash of the client access token'
    end

    return true
end

--
-- Tne entry point to validate token details
--
local function validate(access_token_jwt, dpop_proof_jwt)

    local jwt_obj = jwt:load_jwt(dpop_proof_jwt)
    if not jwt_obj or not jwt_obj.valid then
        return nil, 'DPoP Proof JWT is malformed'
    end

    if not jwt_obj.header then
        return nil, 'DPoP Proof JWT has a missing JWT header'
    end

    if jwt_obj.header.typ ~= 'dpop+jwt' then
        return nil, 'DPoP Proof JWT has an invalid typ value'
    end

    if not jwt_obj.header.jwk then
        return nil, 'DPoP Proof JWT has no jwk'
    end

    if jwt_obj.header.jwk.kty ~= 'EC' then
        return nil, 'DPoP Proof JWT jwk is not an EC key'
    end

    if jwt_obj.header.jwk.crv ~= 'P-256' then
        return nil, 'DPoP Proof JWT jwk is not a P-256 key'
    end

    if not jwt_obj.header.jwk.x or not jwt_obj.header.jwk.y then
        return nil, 'DPoP Proof JWT jwk does not have x and y parameters'
    end

    local jwk_json_string, err1 = cjson.encode({
        crv = jwt_obj.header.jwk.crv,
        kty = jwt_obj.header.jwk.kty,
        x = jwt_obj.header.jwk.x,
        y = jwt_obj.header.jwk.y,
    })
    if not jwk_json_string then
        return nil, "Could not encode JWK: " .. tostring(err1)
    end

    local public_key, err2 = openssl_pkey.new(jwk_json_string, {
        format = 'JWK'
    })
    if not public_key then
        return nil, "Could not import DPoP public key: " .. tostring(err2)
    end

    local public_key_pem, err3 = public_key:to_PEM('public')
    if not public_key_pem then
        return nil, "Could not export public key: " .. tostring(err3)
    end

    local res = jwt:verify_jwt_obj(public_key_pem, jwt_obj)
    if not res.verified then
        return nil, 'DPoP Proof JWT failed validation: ' .. tostring(res.reason)
    end
    local claims = res.payload

    if not claims.jti then
        return nil, 'DPoP Proof JWT has a missing jti claim'
    end

    if not claims.ath then
        return nil, 'DPoP Proof JWT has a missing ath claim'
    end

    local expected_htm = ngx.req.get_method()
    if not claims.htm or claims.htm ~= expected_htm then
        return nil, 'DPoP Proof JWT has an invalid htm claim'
    end

    local host = ngx.var.http_host or ngx.var.server_name
    local expected_htu = ngx.var.scheme .. "://" .. host .. ngx.var.uri
    if not claims.htu or claims.htu ~= expected_htu then
        return nil, 'DPoP Proof JWT has an invalid htu claim'
    end

    if not claims.iat then
        return nil, 'DPoP Proof JWT has a missing iat claim'
    end

    local ok, access_toke_error = validate_access_token(access_token_jwt, jwt_obj.header.jwk, claims.ath)
    if not ok then 
        return nil, access_toke_error
    end

    return claims
end

--
-- The entry point for DPoP processing
--
function _M.run()

    -- Get the JWT access token from the Authorization: DPoP header
    local auth_header = ngx.req.get_headers()['Authorization']
    if not auth_header then
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_token', 'Missing, invalid or expired access token')
    end
    local access_token_jwt = auth_header:match("^%s*[Dd][Pp][Oo][Pp]%s+(.+)%s*$")
    if not access_token_jwt then
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_token', 'Missing, invalid or expired access token')
    end

    -- Get the DPoP proof JWT from the DPoP header
    local dpop_proof_jwt = ngx.req.get_headers()['DPoP']
    if not dpop_proof_jwt then
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_dpop_proof', 'Missing, invalid or expired DPoP proof JWT')
    end

    -- Do token validation
    local dpop_claims, err = validate(access_token_jwt, dpop_proof_jwt)
    if err then
        ngx.log(ngx.WARN, err)
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_dpop_proof', 'Missing, invalid or expired DPoP proof JWT')
    end

    -- Issue a server issued nonce challenge if required
    if not dpop_claims.nonce then
        nonce_challenge_response()
    end

    -- In this example deployment, the target API treats the access token as a bearer token
    ngx.req.set_header('Authorization', 'Bearer ' .. access_token_jwt)
end

return _M
