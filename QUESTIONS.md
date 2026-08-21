# Questions

Anything I am unsure about or which might be an issue will be documented here for wider discussion.  

## User Info and Multiple Requests

When I make multiple user info requests, I get errors if I resend the same nonce.  
This leads to a retry on every single API request to the Curity Identity Server.  
Is that right and can we avoid it?  

## Cache Best Practices

How should I cache nonce and jti values?  
Do we partition by client_id?  
Do we bind the nonce and jti together?  
What times to live do we use?  
