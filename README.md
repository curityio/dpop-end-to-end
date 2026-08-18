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

The API gateway can use a plugin to enforce the token to key binding:

- On every API request the plugin verifies that the current DPoP proof JWT corresponds to the access token's `cnf` claim.
- The plugin also ensures that the DPoP proof JWT contains a fresh server issued nonce.  

### The API

In this example, the API itself only implements the following tasks:

- Standard JWT access token validation.
- Business authorization using claims from the access token.

## Run the Example

Deploy the Curity Identity Server, an API gateway and an example API:

```bash
./deploy.sh
```

Then, run a console application that acts as a DPoP client, to call APIs with sender constrained access tokens:

```bash
cd dpop-client
npm install
npm start
```

The client stores a DPoP signing key and its access token in secure storage, private to the application and user.  
If you re-run the client 5 minutes after user authentication, you will see a server issued nonce event.

## Further Information

- Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
- See the [DPoP Overview](https://curity.io/resources/learn/dpop-overview/) to learn more about Demonstrating Proof of Possession.
- See the [DPoP Code Example](https://curity.io/resources/learn/api-dpop-security) to learn how to secure APIs with Proof of Possession.
