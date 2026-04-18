import cache
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode.{type Decoder}
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/pair
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri
import gose/jose/algorithm
import gose/jose/jwt

pub type IssuerConfig {
  IssuerConfig(
    issuer: String,
    jwks_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
  )
}

pub type ClientConfig {
  ClientConfig(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
  )
}

pub type JwtPayload {
  Payload(
    sub: String,
    aud: String,
    exp: Int,
    iat: Int,
    iss: String,
    nbf: Int,
    jti: String,
    other_claims: Dict(String, Dynamic),
  )
}

@internal
pub fn decoder() -> Decoder(JwtPayload) {
  use dict_obj <- decode.then(decode.dict(decode.string, decode.dynamic))

  use iss <- decode.field("iss", decode.string)
  use sub <- decode.field("sub", decode.string)
  use aud <- decode.field("aud", decode.string)
  use exp <- decode.field("exp", decode.int)
  use nbf <- decode.field("nbf", decode.int)
  use iat <- decode.field("iat", decode.int)
  use jti <- decode.field("jti", decode.string)
  let other_claims =
    dict_obj
    |> dict.delete("iss")
    |> dict.delete("sub")
    |> dict.delete("aud")
    |> dict.delete("exp")
    |> dict.delete("nbf")
    |> dict.delete("iat")
    |> dict.delete("jti")
  decode.success(Payload(
    sub:,
    aud:,
    exp:,
    iat:,
    iss:,
    nbf:,
    jti:,
    other_claims:,
  ))
}

//@internal
pub fn decode_jwt_token(
  token: String,
  config: IssuerConfig,
  validator: jwt.JwtValidationOptions,
  decoder: fn() -> Decoder(a),
) -> Result(a, jwt.JwtError) {
  let assert Ok(algo) = algorithm.signing_alg_from_string("RS256")
  let assert Ok(verifier) =
    jwt.verifier(algo, cache.get_keys(config.jwks_uri), validator)
  let assert Ok(verified) =
    jwt.verify_and_validate(verifier, token, timestamp.system_time())
  jwt.decode(verified, decoder())
}

pub type TokenResponse {
  TokenResponse(
    access_token: String,
    token_type: String,
    expires_in: Int,
    refresh_token: Option(String),
    id_token: Option(String),
  )
}

pub fn form_encode(contents: List(#(String, String))) -> String {
  let str =
    contents
    |> list.filter(fn(s) {
      s |> pair.second |> string.trim() |> string.length > 0
    })
    |> uri.query_to_string
  result.unwrap(uri.percent_decode(str), str)
}

pub fn access_token_response_decoder() -> decode.Decoder(TokenResponse) {
  use access_token <- decode.field("access_token", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  use expires_in <- decode.field("expires_in", decode.int)
  use refresh_token <- decode.field(
    "refresh_token",
    decode.optional(decode.string),
  )
  use id_token <- decode.field("id_token", decode.optional(decode.string))
  decode.success(TokenResponse(
    access_token:,
    token_type:,
    expires_in:,
    id_token:,
    refresh_token:,
  ))
}

pub fn access_token_request(
  base_url: String,
  client_config: ClientConfig,
  auth_code: String,
) -> Result(TokenResponse, String) {
  let request_body =
    [
      #("grant_type", "authorization_code"),
      #("code", auth_code),
      #("client_id", client_config.client_id),
      #("client_secret", client_config.client_secret),
      #("redirect_uri", client_config.redirect_uri),
    ]
    |> form_encode()

  let assert Ok(req) = request.to(base_url)
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_body(request_body)

  case httpc.send(req) {
    Ok(resp) if resp.status >= 200 && resp.status < 300 -> {
      let assert Ok(content_type) = response.get_header(resp, "content-type")
      assert string.contains(content_type, "application/json")
      case json.parse(resp.body, access_token_response_decoder()) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error("Json decode error")
      }
    }

    Ok(resp) -> {
      Error(int.to_string(resp.status) <> " - " <> resp.body)
    }
    Error(_e) -> Error("Network error")
  }
}

pub fn refresh_token_request(
  base_url: String,
  client_config: ClientConfig,
  refresh_token: String,
) -> Result(TokenResponse, String) {
  let request_body =
    [
      #("grant_type", "refresh_token"),
      #("client_id", client_config.client_id),
      #("client_secret", client_config.client_secret),
      #("refresh_token", refresh_token),
    ]
    |> form_encode()

  let assert Ok(req) = request.to(base_url)
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_body(request_body)

  case httpc.send(req) {
    Ok(resp) if resp.status >= 200 && resp.status < 300 -> {
      let assert Ok(content_type) = response.get_header(resp, "content-type")
      assert string.contains(content_type, "application/json")
      case json.parse(resp.body, access_token_response_decoder()) {
        Ok(token) -> {
          Ok(token)
        }
        Error(_e) -> {
          Error("Json decode error")
        }
      }
    }

    Ok(resp) -> Error(int.to_string(resp.status) <> " - " <> resp.body)

    Error(_e) -> Error("Network error")
  }
}

pub fn revoke_token_request(
  base_url: String,
  client_config: ClientConfig,
  access_token: String,
) -> Result(Int, String) {
  let request_body =
    [
      #("client_id", client_config.client_id),
      #("client_secret", client_config.client_secret),
      #("access_token", access_token),
    ]
    |> form_encode()

  let assert Ok(req) = request.to(base_url)
  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_body(request_body)

  case httpc.send(req) {
    Ok(resp) if resp.status >= 200 && resp.status < 300 -> {
      Ok(resp.status)
    }

    Ok(resp) -> Error(int.to_string(resp.status) <> " - " <> resp.body)

    Error(_e) -> Error("Network error")
  }
}

pub fn map_decoder() -> Decoder(Dict(String, Dynamic)) {
  decode.dict(decode.string, decode.dynamic)
}

pub fn get_userinfo(
  base_url: String,
  access_token: String,
) -> Result(Dict(String, Dynamic), String) {
  let assert Ok(req) = request.to(base_url)
  let req =
    req
    |> request.set_method(http.Get)
    |> request.set_header(
      "Authorization",
      string.join(["Bearer", access_token], " "),
    )

  case httpc.send(req) {
    Ok(resp) if resp.status >= 200 && resp.status < 300 -> {
      case decode.run(dynamic.string(resp.body), map_decoder()) {
        Ok(result) -> Ok(result)
        Error(_) -> Error("Error decoding json")
      }
    }

    Ok(resp) -> Error(int.to_string(resp.status) <> " - " <> resp.body)

    Error(_e) -> Error("Network error")
  }
}
