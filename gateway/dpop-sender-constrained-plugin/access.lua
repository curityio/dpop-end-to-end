local _M = {}
local jwt = require 'resty.jwt'
local openssl_pkey = require 'resty.openssl.pkey'
local cjson = require 'cjson.safe'

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
-- Validate the basics of the DPoP proof JWT and return its claims
--
local function validate_dpop_proof_jwt(dpop_proof_jwt)

    local jwt_obj = jwt:load_jwt(dpop_proof_jwt)
    if not jwt_obj then
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
        kty = jwt_obj.header.jwk.kty,
        crv = jwt_obj.header.jwk.crv,
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

    if not claims.htm then
        return nil, 'DPoP Proof JWT has a missing htm claim'
    end

    if not claims.htu then
        return nil, 'DPoP Proof JWT has a missing htu claim'
    end

    if not claims.iat then
        return nil, 'DPoP Proof JWT has a missing iat claim'
    end

    return claims
end

--
-- The entry point for DPoP processing
--
function _M.run(config)

    -- First get the required headers
    local auth_header = ngx.req.get_headers()['Authorization']
    if not auth_header then
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_token', 'Missing, invalid or expired access token')
    end

    local dpop_proof_jwt = ngx.req.get_headers()['DPoP']
    if not dpop_proof_jwt then
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_dpop_proof', 'Missing, invalid or expired DPoP proof JWT')
    end

    -- Do basic validation of the DPoP proof and get its claims
    local dpopClaims, err = validate_dpop_proof_jwt(dpop_proof_jwt)
    if err then
        ngx.log(ngx.WARN, err)
        error_response(ngx.HTTP_UNAUTHORIZED, 'invalid_dpop_proof', 'Missing, invalid or expired DPoP proof JWT')
    end

    -- Validate the access token to DPoP proof relationship
    
    local scheme, access_token = auth_header:match("^%s*(%S+)%s+(.+)%s*$")
    ngx.req.set_header('Authorization', 'Bearer ' .. access_token)
end

return _M
