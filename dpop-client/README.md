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
  "jti": "bf30b56d-56e3-4c19-86f8-12c27f277dbd",
  "delegationId": "ac10ce35-05b1-45cb-b291-8169b6b8bbc9",
  "exp": 1787066361,
  "nbf": 1787065461,
  "scope": "openid profile retail/orders",
  "iss": "https://login.demo.example/oauth/v2/oauth-anonymous",
  "sub": "fred",
  "aud": [
    "dpop-client",
    "https://api.demo.example/orders"
  ],
  "iat": 1787065461,
  "purpose": "access_token",
  "cnf": {
    "jkt": "eywqMwZfUtgXL9e-2Cn7sqc7W0B2Dfy_RUAeSf1RkfE"
  },
  "customer_id": "102"
}
```

## Further Information