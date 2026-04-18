import auth_provider.{type ClientConfig}
import cache
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode.{type Decoder}
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import google
import gose/jose/jwt.{type JwtError}

pub type JwtPayload {
  GoogleUser(google.JwtPayload)
  AuthUser(auth_provider.JwtPayload)
}

pub type Issuer {
  Google
  OauthProvider(config: auth_provider.IssuerConfig)
}

/// Decode a jwt token with default validation and a default decoder
pub fn decode_jwt_token(issuer: Issuer, token: String) {
  case issuer {
    Google -> {
      let validator =
        jwt.JwtValidationOptions(
          ..jwt.default_validation(),
          issuer: option.Some(google.config.issuer),
        )
      result.try(
        auth_provider.decode_jwt_token(
          token,
          google.config,
          validator,
          google.decoder,
        ),
        fn(p) { Ok(GoogleUser(p)) },
      )
    }
    OauthProvider(config) -> {
      let validator =
        jwt.JwtValidationOptions(
          ..jwt.default_validation(),
          issuer: option.Some(config.issuer),
        )
      result.try(
        auth_provider.decode_jwt_token(
          token,
          google.config,
          validator,
          auth_provider.decoder,
        ),
        fn(p) { Ok(AuthUser(p)) },
      )
    }
  }
}

/// Decode a jwt token with a custom decoder
pub fn decode_jwt_token_as(
  issuer: Issuer,
  token: String,
  decoder: fn() -> Decoder(a),
) -> Result(a, jwt.JwtError) {
  case issuer {
    Google -> {
      let validator =
        jwt.JwtValidationOptions(
          ..jwt.default_validation(),
          issuer: option.Some(google.config.issuer),
        )
      auth_provider.decode_jwt_token(token, google.config, validator, decoder)
    }
    OauthProvider(config) -> {
      let validator =
        jwt.JwtValidationOptions(
          ..jwt.default_validation(),
          issuer: option.Some(config.issuer),
        )
      auth_provider.decode_jwt_token(token, config, validator, decoder)
    }
  }
}

/// Decode a jwt token with validation 
pub fn decode_jwt_token_and_validate(
  issuer: Issuer,
  token: String,
  validator: jwt.JwtValidationOptions,
) -> Result(JwtPayload, jwt.JwtError) {
  case issuer {
    Google -> {
      result.try(
        auth_provider.decode_jwt_token(
          token,
          google.config,
          validator,
          google.decoder,
        ),
        fn(p) { Ok(GoogleUser(p)) },
      )
    }
    OauthProvider(config) -> {
      result.try(
        auth_provider.decode_jwt_token(
          token,
          config,
          validator,
          auth_provider.decoder,
        ),
        fn(p) { Ok(AuthUser(p)) },
      )
    }
  }
}

/// Decode a jwt token with validation and custom decoder
pub fn decode_jwt_token_and_validate_as(
  issuer: Issuer,
  token: String,
  validator: jwt.JwtValidationOptions,
  decoder: fn() -> Decoder(a),
) -> Result(a, jwt.JwtError) {
  case issuer {
    Google -> {
      auth_provider.decode_jwt_token(token, google.config, validator, decoder)
    }
    OauthProvider(config) -> {
      auth_provider.decode_jwt_token(token, config, validator, decoder)
    }
  }
}

/// Access token request
/// https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
pub fn access_token_request(
  issuer: Issuer,
  client_config: ClientConfig,
  auth_code: String,
) {
  let base_url = case issuer {
    Google -> google.config.token_endpoint
    OauthProvider(config) -> config.token_endpoint
  }
  auth_provider.access_token_request(base_url, client_config, auth_code)
}

/// Refresh token request
/// https://datatracker.ietf.org/doc/html/rfc6749#section-6
pub fn refresh_token_request(
  issuer: Issuer,
  client_config: ClientConfig,
  refresh_token: String,
) {
  let base_url = case issuer {
    Google -> google.config.token_endpoint
    OauthProvider(config) -> config.token_endpoint
  }
  auth_provider.refresh_token_request(base_url, client_config, refresh_token)
}

/// Revokes an issued access/refresh token
/// https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
pub fn revoke_token_request(
  issuer: Issuer,
  client_config: ClientConfig,
  access_token: String,
) {
  let base_url = case issuer {
    Google -> google.config.revocation_endpoint
    OauthProvider(config) -> config.revocation_endpoint
  }
  auth_provider.revoke_token_request(base_url, client_config, access_token)
}

/// The UserInfo endpoint is an OAuth 2.0 protected resource of the identity server where client applications can retrieve consented claims (assertions), about the logged in end-user.
/// The claims are packaged in a JSON object where the sub member represents the subject (end-user) identifier.
/// 
pub fn get_userinfo(issuer: Issuer, access_token: String) {
  let base_url = case issuer {
    Google -> google.config.userinfo_endpoint
    OauthProvider(config) -> config.userinfo_endpoint
  }
  auth_provider.get_userinfo(base_url, access_token)
}

/// Make authorization url according to https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
/// 
pub fn authorize_url(
  issuer: Issuer,
  client_config: ClientConfig,
  state_params: List(#(String, String)),
) -> String {
  let base_url = case issuer {
    Google -> google.config.authorization_endpoint
    OauthProvider(config) -> config.authorization_endpoint
  }
  let scopes =
    client_config.scopes
    |> list.map(string.trim)
    |> string.join(with: "+")
    |> fn(scopes) {
      case string.length(scopes) > 0 {
        True -> [#("scope", scopes)]
        False -> []
      }
    }

  let query_string =
    [
      #("response_type", "code"),
      #("client_id", client_config.client_id),
      #("redirect_uri", client_config.redirect_uri),
    ]
    |> list.append(scopes)
    |> list.append(state_params)
    |> auth_provider.form_encode()

  string.join([base_url, query_string], with: "?")
}

/// Decode jwt. Jwt will be unverified and decoded as a Dict.
/// 
pub fn decode_unverified_jwt_token(
  token: String,
) -> Result(Dict(String, Dynamic), JwtError) {
  decode_unverified_jwt_token_as(token, auth_provider.map_decoder)
}

/// Decode jwt. Jwt will be unverified and decoded using given decoder.
/// 
pub fn decode_unverified_jwt_token_as(
  token: String,
  decoder: fn() -> Decoder(a),
) -> Result(a, JwtError) {
  let assert Ok(jwt_) = jwt.parse(token)
  jwt.dangerously_decode_unverified(jwt_, decoder())
}

/// The ets table used as cache will need to be cleaned up
/// 
pub fn cleanup_cache() {
  cache.cleanup()
}
