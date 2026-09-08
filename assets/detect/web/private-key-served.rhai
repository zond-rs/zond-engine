// Private key served in an HTTP response.
//
// A PEM private-key block in a response body is a direct key disclosure: whoever
// reads it can impersonate the service or decrypt its traffic. Matched on the PEM
// header shape, so the whole key does not have to be captured.

fn first_http_text(responses) {
    for raw in responses {
        if http_response(raw) != () { return text(raw); }
    }
    ""
}

fn analyze(ctx, responses) {
    let body = first_http_text(responses).to_lower();
    if body == "" { return []; }
    if !re_is_match("-----begin [a-z0-9 ]*private key-----", body) { return []; }

    [ #{
        severity: "critical",
        summary: "A PEM private key is served in the response body",
        detail: "the response body contains a private-key block, a direct disclosure of the key itself",
        references: [ #{ cwe: 312 } ],
    } ]
}
