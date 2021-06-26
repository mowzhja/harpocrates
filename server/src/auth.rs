/// Takes care of the initial authentication procedure between it and the client.
///
/// The processing of the various network messages is left to lib.rs.
use bytes::Bytes;

/// Checks whether the credentials provided by the user are valid.
fn auth(data: Bytes) -> bool {
    // to get the username/hash/useful data out of raw
    parse_raw_data(data);

    send_challenge();
    get_response();

    if response_valid() {
        true
    } else {
        false
    }
}
