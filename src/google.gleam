import auth_provider
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode

pub type JwtPayload {
  JwtPayload(
    sub: String,
    aud: String,
    exp: Int,
    iat: Int,
    iss: String,
    nbf: Int,
    name: String,
    family_name: String,
    given_name: String,
    email: String,
    email_verified: Bool,
    picture: String,
    other_claims: Dict(String, Dynamic),
  )
}

// https://accounts.google.com/.well-known/openid-configuration
@internal
pub const config = auth_provider.IssuerConfig(
  issuer: "https://accounts.google.com",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
  revocation_endpoint: "https://oauth2.googleapis.com/revoke",
)

@internal
pub fn decoder() -> decode.Decoder(JwtPayload) {
  use dict_obj <- decode.then(decode.dict(decode.string, decode.dynamic))
  use sub <- decode.field("sub", decode.string)
  use aud <- decode.field("aud", decode.string)
  use exp <- decode.field("exp", decode.int)
  use iat <- decode.field("iat", decode.int)
  use nbf <- decode.field("nbf", decode.int)
  use iss <- decode.field("iss", decode.string)
  use name <- decode.field("name", decode.string)
  use family_name <- decode.field("family_name", decode.string)
  use given_name <- decode.field("given_name", decode.string)
  use email <- decode.field("email", decode.string)
  use email_verified <- decode.field("email_verified", decode.bool)
  use picture <- decode.field("picture", decode.string)

  let other_claims =
    dict_obj
    |> dict.delete("iss")
    |> dict.delete("sub")
    |> dict.delete("aud")
    |> dict.delete("exp")
    |> dict.delete("nbf")
    |> dict.delete("iat")
    |> dict.delete("jti")
    |> dict.delete("name")
    |> dict.delete("given_name")
    |> dict.delete("family_name")
    |> dict.delete("email")
    |> dict.delete("email_verified")
    |> dict.delete("picture")

  decode.success(JwtPayload(
    sub:,
    nbf:,
    aud:,
    exp:,
    iat:,
    iss:,
    name:,
    family_name:,
    given_name:,
    email:,
    email_verified:,
    picture:,
    other_claims:,
  ))
}
