local _M = {}

function _M.run(config)

    local auth_header = ngx.req.get_headers()['Authorization']
    if auth_header then
        
        local scheme, access_token = auth_header:match("^%s*(%S+)%s+(.+)%s*$")

        -- Validate that lower case scheme is dpop

        -- Return error responses

        -- Code the DPoP validation

        -- Do server issued nonce handling and challenge responses

        -- Now that the DPoP specific validation is done, the target API can treat the access token as a bearer token
        ngx.req.set_header('Authorization', 'Bearer ' .. access_token)
    end
end

return _M
