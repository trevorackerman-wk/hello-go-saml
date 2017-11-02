# Proof of concept SAML SSO with go

I used okta's example python and saml2 SP application to figure out how to have a minimal proof of concept SP in go to do single sign on.
It passes most of the security tests from saml.oktadev.com, anything that fails is because we send back unauthorized so at least it errors on the side of being too restrictive instead of too open.
Failing saml.oktadev.com security checks
- It doesn't support the re-signed assertion in the saml response, signature's in a different place and the response didn't have an obvious reference id to what the signature is applied to. (we send back 401)
- It doesn't support compressed authentication requests (we send back 401)

Much of this came from the robots and pencils repo
https://github.com/RobotsAndPencils/go-saml

This also works with okta developer organization.
Remember to use ngrok to expose this local service to the internet so saml.oktadev.com can talk back to it.
