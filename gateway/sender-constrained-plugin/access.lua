local _M = {}

function _M.run(config)

    ngx.log(ngx.WARN, '*** IN SENDER CONSTRAINED ***')

    local auth_header = ngx.req.get_headers()['Authorization']
    if auth_header and string.len(auth_header) > 5 and string.lower(string.sub(auth_header, 1, 5)) == 'dpop ' then

        -- Get the incoming sender constrained access token
        local access_token = string.sub(auth_header, 6)

        -- Validate that the cnf claim matches the thumbprint from the JWT header

        -- Now that the DPoP specific validation is done, the target API can treat the access token as a bearer token
        ngx.req.set_header('Authorization', 'Bearer ' .. access_token)

    else
        ngx.log(ngx.WARN, 'No valid sender constrained access token was found in the HTTP Authorization header')
        unauthorized_error_response(config)
    end
end

return _M
