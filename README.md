# DPoP End to End

An end-to-end example that demonstrates DPoP mechanics, for a client that calls an internet API.

## DPoP Flow

The following diagram illustrates one possible deployment:

![DPoP Flow](dpop-flow.png)

### The Client

The client must use libraries to do additional work:

- Create and store a key with which to sign DPoP proof JWTs.
- Handle additional error responses from servers, to process server issued nonces.

### The API Gateway

The API gateway can use a plugin, that runs during API requests, to enforce the token to DPoP key binding:

- The plugin verifies that the current DPoP proof JWT corresponds to the access token's `cnf` claim.
- The plugin also ensures that the DPoP proof JWT contains a fresh server-issued nonce.  

### The API

In this example, the API itself only implements the following standard tasks:

- JWT access token validation.
- Business authorization using claims from the access token.

## Run the Example

First provide an environment variable that points to a license file for the Curity Identity Server.  
If required, download one from the [Curity Developer Portal](https://developer.curity.io/).

```bash
export LICENSE_FILE_PATH=~/Desktop/license.json
```

Deploy and deploy the Curity Identity Server, an API gateway and an example API:

```bash
./build.sh
./deploy.sh
```

Then, run a console application that acts as a DPoP client, to call APIs with sender-constrained access tokens:

```bash
cd dpop-client
npm install
npm start
```

The client receives an opaque access tokens and outputs it for visualization purposes:

```bash
Received opaque access token: _0XBPWQQ_5557c7ae-f50c-4fd7-a8ae-33ec7dcf3445
```

A real DPoP client would not be able to view the JWT access token that corresponds to the opaque access token.  
For visualization purposes, the demo acts as an API gateway to introspect the opaque access token.  
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

The client sends its opaque access token in the HTTP `Authorization` header.  
The client also sends a DPoP proof JWT in the HTTP `DPoP` header.  
Before the client can successfully interact with the API, the following actions take place:

- The API gateway validates the DPoP proof and checks it contains a fresh server-issued nonce.
- If there is no valid nonce, the server issues an HTTP 400 response with a new server-issued nonce.
- The client must resend the request with a new DPoP proof JWT that contains the server-issued nonce.
- The API gateway then introspects the access token and forwards a JWT access token to the API.
- The API validates the JWT access token and implements business authorization using access token claims.

After all security checks pass, the client receives authorized data from the API:

```json
[
  {
    "customerId": "102",
    "productId": "XM0922",
    "amountUSD": 30000
  },
  {
    "customerId": "102",
    "productId": "LK9834",
    "amountUSD": 45000
  }
]
```

If a malicious party somehow intercepts the access token, they will be unable to use it to gain API access.   
To do so, the malicious party would need the genuine client's cryptographic key as well as its access token.

## Further Information

- Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
- See the [DPoP Overview](https://curity.io/resources/learn/dpop-overview/) to learn more about Demonstrating Proof of Possession.
- See the [DPoP Code Example](https://curity.io/resources/learn/api-dpop-security) to learn how to secure APIs with Proof of Possession.
