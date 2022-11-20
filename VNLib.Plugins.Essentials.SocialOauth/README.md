# VNLib.Plugins.Essentials.SocialOauth

A basic external OAuth2 authentication plugin. 

## Plugin Mode

This library exports an IPlugin type that may be loaded directly by a host application, or 
imported to provide base classes for creating OAuth2 authentication endpoints.

By default, exports 2 endpoints for Github and Discord authentication. Configuration 
variables for either endpoint may be omitted or included to export endpoints.

## Library Mode

Exports SocialOAuthBase to provide a base class for creating OAuth2 authentication 
endpoints, that is compatible with the VNLib web client library authentication flow


## Authentication Flow

The authentication flow works similar to the local account mechanism with an extra step that helps
guard against replay, and MITM attacks. When an request claim is made (request to login) from client
side code (via put request), a browser id is request (for login flow) along with the clients encryption
public key (same key as Essentials.Accounts requires). The public key is used to encrypted a derived
redirect url, which includes a "secret" state token (OAuth2 standard state) that only the private-key
holder should be able to recover. When decrypted, should be used to redirect the client's browser to 
the remote authentication server. Assuming the request is granted, the browser is redirected to the 
originating endpoint, and the nonce is used to recover the initial claim and the flow continues. The 
request should also include the required OAuth2 'code' parameter used to exchange for an access token.
If the access token is granted, a nonce is generated, passed to the browser via a redirect query parameter
which the browser code will use in a POST request to the endpoint to continue the flow. The nonce is 
used to recover the access token and original claim data (public key, browser id, etc), which is used
to recover a user account, or optionally create a new account. Once complete, the user account is used
to upgrade the session and grant authorization to the client. The public key (and browser id) is used
from the initial claim to authorize the session, which should guard against MITM, replay, and forgery 
attacks. However this only works if we assume the clients private key has not been stolen, which is a 
much larger issue and should be addressed separately. 

## Diagram

PUT -> { public_key, browser_id } -> server -> { result: "base64 encrypted redirect url"} -> 
    OAuth2Server -> redirect -> "?code=some_code&state=decrypted_state_token"

GET -> "?code=some_code&state=decrypted_state_token" -> server -> "?result=authorized&nonce=some_nonce"
POST -> { nonce:"some_nonce" } -> server -> [authorization complete message]