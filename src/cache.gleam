import carpenter/table
import gleam/dynamic/decode
import gleam/float
import gleam/http/request
import gleam/http/response
import gleam/httpc
import gleam/int
import gleam/json
import gleam/option
import gleam/regexp.{Match}
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp
import gose/jose/jwk

fn make_month(mmm: String) {
  case mmm {
    "Jan" -> calendar.January
    "Feb" -> calendar.February
    "Mar" -> calendar.March
    "Apr" -> calendar.April
    "May" -> calendar.May
    "Jun" -> calendar.June
    "Jul" -> calendar.July
    "Aug" -> calendar.August
    "Sep" -> calendar.September
    "Oct" -> calendar.October
    "Nov" -> calendar.November
    "Dec" -> calendar.December
    _ -> panic as "Invalid month in cache header "
  }
}

/// Regex to extract max-age from cache-control header and convert to unix_seconds
/// public, max-age=25171, must-revalidate, no-transform
/// 
fn find_max_age(str: String) {
  let pattern = "max-age=(\\d+)"
  let assert Ok(re) = regexp.from_string(pattern)

  let matches = regexp.scan(re, str)

  // Each match contains the full string and a list of sub-captures
  case matches {
    [Match(_, [option.Some(seconds)]), ..] -> {
      let assert Ok(secs) = int.parse(seconds)
      timestamp.system_time()
      |> timestamp.add(duration.seconds(secs))
      |> timestamp.to_unix_seconds()
    }
    _ ->
      timestamp.system_time()
      |> timestamp.add(duration.minutes(60))
      |> timestamp.to_unix_seconds()
  }
}

/// Convert expiry string timestamp to unix_seconds
/// Sat, 18 Apr 2026 22:34:54 GMT
/// 
fn find_cache_expiry(str: String) {
  let pattern = "^\\w{3}, (\\d+) (\\w{3}) (\\d{4}) (\\d{2}):(\\d{2}):(\\d{2})"

  let assert Ok(re) = regexp.from_string(pattern)

  let matches = regexp.scan(re, str)

  // Each match contains the full string and a list of sub-captures
  case matches {
    [
      Match(
        _,
        [
          option.Some(dt),
          option.Some(mmm),
          option.Some(year),
          option.Some(hh),
          option.Some(mm),
          option.Some(ss),
        ],
      ),
      ..
    ] -> {
      let assert Ok(year_) = int.parse(year)
      let assert Ok(dt_) = int.parse(dt)
      let assert Ok(hh_) = int.parse(hh)
      let assert Ok(mm_) = int.parse(mm)
      let assert Ok(ss_) = int.parse(ss)
      let mmm_ = make_month(mmm)
      let ts =
        timestamp.from_calendar(
          date: calendar.Date(year_, mmm_, dt_),
          time: calendar.TimeOfDay(hh_, mm_, ss_, 0),
          offset: calendar.utc_offset,
        )
      timestamp.to_unix_seconds(ts)
    }
    _ ->
      timestamp.system_time()
      |> timestamp.add(duration.minutes(60))
      |> timestamp.to_unix_seconds()
  }
}

/// Get expires and cache-control headers and get the maximum expiry time in unix_seconds 
/// 
fn make_exp(resp: response.Response(a)) {
  case
    response.get_header(resp, "cache-control"),
    response.get_header(resp, "expires")
  {
    Ok(max_age_str), Ok(expiry_str) -> {
      let age_expiry = find_max_age(max_age_str)
      let date_expiry = find_cache_expiry(expiry_str)
      float.max(age_expiry, date_expiry)
    }
    Ok(max_age_str), _ -> {
      find_max_age(max_age_str)
    }
    _, Ok(expiry_str) -> {
      find_cache_expiry(expiry_str)
    }
    _, _ -> {
      timestamp.system_time()
      |> timestamp.add(duration.minutes(60))
      |> timestamp.to_unix_seconds()
    }
  }
}

/// Get public keys from jwks_uri for the open-id provider 
/// 
pub fn get_keys_http(uri: String) {
  let assert Ok(base_req) = request.to(uri)

  let req =
    request.prepend_header(base_req, "accept", "application/vnd.api+json")

  let assert Ok(resp) = httpc.send(req)

  assert resp.status == 200

  let assert Ok(content_type) = response.get_header(resp, "content-type")
  assert string.contains(content_type, "application/json")

  let expiry = make_exp(resp) |> float.to_string()

  #(expiry, resp.body)
}

/// The public jwks keys of the oauth provider are fetched from supplied jwks uri and stored in a public ets table
/// The ets table will need to be cleaned up
/// 
@internal
pub fn get_keys(jwks_uri: String) {
  let assert Ok(ets_) = table.ref("oauth_client_gleam")
  let object = table.lookup(ets_, jwks_uri)
  let resp = case object {
    [#(_, #(expiry, keys))] -> {
      echo "cached keys"
      let now = timestamp.system_time() |> timestamp.to_unix_seconds()
      let assert Ok(expiry_) = float.parse(expiry)
      case expiry_ <. now {
        True -> {
          let #(expiry, keys) = get_keys_http(jwks_uri)
          table.insert(ets_, [#(jwks_uri, #(expiry, keys))])
          keys
        }
        False -> keys
      }
    }
    _ -> {
      echo "http keys"
      let #(expiry, keys) = get_keys_http(jwks_uri)
      table.insert(ets_, [#(jwks_uri, #(expiry, keys))])
      keys
    }
  }

  let assert Ok(keys) = json.parse(from: resp, using: keys_decoder())
  keys
}

fn keys_decoder() {
  use keys <- decode.field("keys", decode.list(of: jwk.decoder()))
  decode.success(keys)
}

/// The ets table used as cache will need to be cleaned up
/// 
@internal
pub fn cleanup() {
  result.try(table.ref("oauth_client_gleam"), fn(set) {
    table.drop(set) |> Ok()
  })
}

/// Create ets table 
/// 
@internal
pub fn init() {
  let assert Ok(cache_) =
    table.build("oauth_client_gleam")
    |> table.privacy(table.Public)
    |> table.write_concurrency(table.AutoWriteConcurrency)
    |> table.read_concurrency(True)
    |> table.decentralized_counters(True)
    |> table.compression(False)
    |> table.set
  cache_
}
