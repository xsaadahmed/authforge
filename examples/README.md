# Demo relying party and resource server

Two deliberately minimal FastAPI apps whose only purpose is to prove the IdP works end to end
against code that does not import it. Neither is a product, and neither shares a line of code with
`app/` — that separation is the point, because a client that reuses the server's internals proves
nothing about interoperability.

| App | Port | Role |
|---|---|---|
| `demo_rp.py` | 8100 | Relying party. Discovers the IdP, runs Authorization Code + PKCE, validates the ID token, calls the resource server. |
| `demo_resource_server.py` | 8200 | Resource server. Protects one endpoint with the IdP's access tokens, verified against JWKS. |

## What the RP demonstrates

- Reading `/.well-known/openid-configuration` instead of hard-coding endpoints.
- Generating a PKCE verifier, sending only the S256 challenge.
- Generating `state` and `nonce`, and rejecting a callback whose `state` it did not issue.
- Exchanging the code with `client_secret_basic`.
- Validating the ID token's signature against JWKS plus `iss`, `aud`, `exp` and `nonce`.
- Using the refresh token, and showing that the old one stops working after rotation.

## What the resource server demonstrates

The validation any resource server must perform, with no shared code and no calls back to the IdP
on the request path:

1. Fetch JWKS once and cache it (a token's `kid` selects the key).
2. Verify the RS256 signature.
3. Check `iss` matches the configured issuer and `aud` contains this API's own identifier.
4. Check `exp`/`nbf`.
5. Check the required scope is present, answering `insufficient_scope` if not.

Step 3 is the one most often skipped: without the audience check, a token minted for a *different*
API of the same issuer would be accepted here.

## Running it

With the stack up (`make up`) and seeded (`make seed`):

```bash
export AUTHFORGE_DEMO_CLIENT_SECRET="<the secret printed by make seed>"
make demo
```

Then open <http://localhost:8100>. The RP prints every step, including the decoded token claims, so
the flow is inspectable rather than magic.
