# oauth2_client_gleam

The package contains helper functions necessary to do oauth2.0 access using authorization code grant flow.

[Authorization Code Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1)


[![Package Version](https://img.shields.io/hexpm/v/oauth2_client_gleam)](https://hex.pm/packages/oauth2_client_gleam)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/oauth2_client_gleam/)

```sh
// Only for erlang target

gleam add oauth2_client_gleam@1

```

Further documentation can be found at <https://hexdocs.pm/oauth2_client_gleam>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```

## Usage
```gleam
import oauth2_client_gleam
import auth_provider
import gleam/dynamic/decode
import gleam/option
import gleam/result
import gleeunit
import google
import gose/jose/jwt
import oauth2_client_gleam.{Google} as src

pub fn main() -> Nil {
  
  // Make a client configuration
  
  let client_config =
    auth_provider.ClientConfig(
      client_id: "---",
      client_secret: "---",
      redirect_uri: "https://redirect_uri",
      scopes: ["openid", "email", "profile"],
    )
  
  // Make authorization url string
  
  let _authorize_url =
    src.authorize_url(Google, client_config, [#("state", "---"), #("nonce", "")])

  // Parse authorization json response to get the auth code jwt token

  let _authorization_code_response =
    decode.run(http_request.body, src.authorization_response_decoder())

  // Decode authorization code jwt to inspect the payload

  let validator =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer: option.Some("https://accounts.google.com"),
    )

  let assert Ok(_jwt_payload) = src.decode_jwt_token(Google, auth_code)
  let assert Ok(_jwt_payload) =
    src.decode_jwt_token_as(Google, auth_code, google.decoder)
  let assert Ok(_jwt_payload) =
    src.decode_jwt_token_and_validate(Google, auth_code, validator)
  let assert Ok(_jwt_payload) =
    src.decode_jwt_token_and_validate_as(
      Google,
      auth_code,
      validator,
      google.decoder,
    )

  // For custom oauth providers whose configurations are not part of the library

  let config =
    auth_provider.IssuerConfig(
      jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
      issuer: "https://accounts.google.com",
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      revocation_endpoint: "https://oauth2.googleapis.com/revoke",
    )
  let assert Ok(resp) =
    src.decode_jwt_token(src.OauthProvider(config), auth_code)


  // Exchange authorization code for access token
  
  let client_config =
    auth_provider.ClientConfig(
      client_id: "---",
      client_secret: "---",
      redirect_uri: "https://redirect_uri",
      scopes: ["openid", "email", "profile"],
    )
  let assert Ok(token_response) =
    src.access_token_request(Google, client_config, auth_code)

  // Get userinfo from provider using access_token
  
  let assert Ok(_userinfo) =
    src.get_userinfo(Google, token_response.access_token)

  // Refresh tokens
  
  let assert Ok(_tokens) =
    token_response.refresh_token
    |> option.to_result("Refresh token not found")
    |> result.try(fn(token) {
      src.refresh_token_request(Google, client_config, token)
    })

  // Revoke tokens
  
  let assert Ok(_userinfo) =
    src.revoke_token_request(Google, client_config, token_response.access_token)

  // Dirty decoding of jwt token
  
  let assert Ok(_jwt_payload) =
    src.decode_unverified_jwt_token(token_response.access_token)
  let assert Ok(_jwt_payload) =
    src.decode_unverified_jwt_token_as(
      token_response.access_token,
      google.decoder,
    )

  // Cleanup
  // The certificate cache uses an ets table which needs to be cleaned up
  
  let assert Ok(_) = src.cleanup_cache()
}
```
