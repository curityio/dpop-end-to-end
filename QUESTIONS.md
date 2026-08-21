# Questions

Anything I am unsure about or which might be an issue will be documented here for wider discussion.  

## User Info and Multiple Requests

When I make multiple user info requests, I get errors if I resend the same nonce.  
This leads to a retry on every single API request to the Curity Identity Server.  
Is that right and can we avoid it?  

## Add ath to JWT

Can we add the ath claim of the opaque access token to the JWT access token?
This would simplify resource server validation.

## Cache Best Practices

How should I form nonce values and cache nonce and jti values?  
Compare to the Curity Identity Server and ask Krzysztof.  