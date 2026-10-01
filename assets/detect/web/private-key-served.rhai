// Private key served in an HTTP response.
//
// A PEM private-key block in a response body is a direct key disclosure: whoever
// reads it can impersonate the service or decrypt its traffic. Only a whole block
// counts: the BEGIN line, a base64 body, and the END line naming the same label.
// The BEGIN line alone is not a key; JavaScript crypto libraries such as jsencrypt
// carry it as a string to build their export with. Lines may be broken by a
// newline or, in a script or JSON string, by a written `\n`.

// The labels a PEM private key is written under.
fn labels() {
    [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    ]
}

fn first_http_text(responses) {
    for raw in responses {
        if http_response(raw) != () { return text(raw); }
    }
    ""
}

// A whole block under `label`: optional `Name: value` headers, then base64 lines,
// at least one of them full-length, then the matching END line.
fn block(label) {
    let gap = "(?:\\s|\\\\[rn])+";
    "-----BEGIN " + label + "-----" + gap
        + "(?:[A-Za-z][A-Za-z-]*: ?[^\\r\\n\\\\]*" + gap + ")*"
        + "(?:[A-Za-z0-9+/]{48,}={0,2}" + gap + ")+"
        + "(?:[A-Za-z0-9+/]+={0,2}" + gap + ")?"
        + "-----END " + label + "-----"
}

fn analyze(ctx, responses) {
    let body = first_http_text(responses);
    if body == "" { return []; }

    for label in labels() {
        if re_is_match(block(label), body) {
            return [ #{
                severity: "critical",
                summary: "A PEM private key is served in the response body",
                detail: "the response body contains a whole " + label + " block, a direct disclosure of the key itself",
                references: [ #{ cwe: 312 } ],
            } ];
        }
    }
    []
}
