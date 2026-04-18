// import auth_provider
// import gleam/dynamic/decode
// import gleam/option
// import gleam/result
import auth_provider
import gleam/string
import gleeunit
import google

// import gose/jose/jwt
// import oauth2_client_gleam.{Google} as src
import oauth2_client_gleam as src

pub fn main() -> Nil {
  gleeunit.main()
}

const auth_code = ".."

// // gleeunit test functions end in `_test`

pub fn decode_unverified_test() {
  let assert Ok(_resp) = src.decode_jwt_token(src.Google, auth_code)
}
// pub fn decode_unverified_payload_test() {
//   let assert Ok(resp) =
//     src.decode_unverified_jwt_token_as(auth_code, google.decoder)
//   string.inspect(resp) |> echo
//   True
// }
// pub fn access_token_test() {
//   let config =
//     auth_provider.ClientConfig(
//       client_id: "",
//       client_secret: "",
//       redirect_uri: "",
//       scopes: [],
//     )
//   let resp = src.access_token_request(src.Google, config, auth_code)
//   string.inspect(resp) |> echo
// }
// pub fn google_test() {
//   // Make authorization url string
//   let client_config =
//     auth_provider.ClientConfig(
//       client_id: "---",
//       client_secret: "---",
//       redirect_uri: "https://redirect_uri",
//       scopes: ["openid", "email", "profile"],
//     )
//   let _authorize_url =
//     src.authorize_url(Google, client_config, [#("state", "---"), #("nonce", "")])

//   // let _authorization_code_response =
//   //   decode.run(http_request.body, src.authorization_response_decoder())

//   // Decode authorization code jwt to inspect the payload
//   let validator =
//     jwt.JwtValidationOptions(
//       ..jwt.default_validation(),
//       issuer: option.Some("https://accounts.google.com"),
//     )
//   let assert Ok(_jwt_payload) = src.decode_jwt_token(Google, auth_code)
//   let assert Ok(_jwt_payload) =
//     src.decode_jwt_token_as(Google, auth_code, google.decoder)
//   let assert Ok(_jwt_payload) =
//     src.decode_jwt_token_and_validate(Google, auth_code, validator)
//   let assert Ok(_jwt_payload) =
//     src.decode_jwt_token_and_validate_as(
//       Google,
//       auth_code,
//       validator,
//       google.decoder,
//     )

//   // Exchange authorization code for access token
//   //
//   let client_config =
//     auth_provider.ClientConfig(
//       client_id: "---",
//       client_secret: "---",
//       redirect_uri: "https://redirect_uri",
//       scopes: ["openid", "email", "profile"],
//     )
//   let assert Ok(token_response) =
//     src.access_token_request(Google, client_config, auth_code)

//   // Get userinfo from provider using access_token
//   //
//   let assert Ok(_userinfo) =
//     src.get_userinfo(Google, token_response.access_token)

//   // Refresh tokens
//   //
//   let assert Ok(_tokens) =
//     token_response.refresh_token
//     |> option.to_result("Refresh token not found")
//     |> result.try(fn(token) {
//       src.refresh_token_request(Google, client_config, token)
//     })

//   // Refresh tokens
//   //
//   let assert Ok(_userinfo) =
//     src.revoke_token_request(Google, client_config, token_response.access_token)

//   // Dirty decoding of jwt token
//   // 
//   let assert Ok(_jwt_payload) =
//     src.decode_unverified_jwt_token(token_response.access_token)
//   let assert Ok(_jwt_payload) =
//     src.decode_unverified_jwt_token_as(
//       token_response.access_token,
//       google.decoder,
//     )

//   True
// }

// pub fn auth_test() {
//   let config =
//     auth_provider.IssuerConfig(
//       jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
//       issuer: "https://accounts.google.com",
//       authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
//       token_endpoint: "https://oauth2.googleapis.com/token",
//       userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
//       revocation_endpoint: "https://oauth2.googleapis.com/revoke",
//     )
//   let assert Ok(resp) =
//     src.decode_jwt_token(src.OauthProvider(config), auth_code)
//   echo resp

//   True
// }
