# DPoP Console Client

A console client that uses DPoP to call APIs with sender-constrained access tokens.

## Usage

To run the console client, first install Node.js 24 or later and clone this repository.\
Then open a command shell in this folder and run `npm install`.

## Run the DPoP Flow

Run a DPoP code flow with the following command:

```bash
npm start
```

The client receives an opaque access tokens and outputs it for visualization purposes:

```bash
Received opaque access token: _0XBPWQQ_5557c7ae-f50c-4fd7-a8ae-33ec7dcf3445
```

A real DPoP client would not be able to view the JWT access token details, but for convenience the example allows the client to do so.  
Notice that the access token has a `cnf` claim that the API gateway can verify:

```json
{
  "sub": "fred",
  "purpose": "access_token",
  "iss": "https://login.demo.example/oauth/v2/oauth-anonymous",
  "active": true,
  "token_type": "bearer",
  "client_id": "dpop-client",
  "aud": [
    "console-client",
    "https://api.demo.example/orders"
  ],
  "nbf": 1787049814,
  "scope": "openid profile retail/orders",
  "exp": 1787050714,
  "delegationId": "ed4f08c5-2c6a-4154-8d5b-157de07cc9a3",
  "iat": 1787049814
}
```

## Further Information