// API key or cloud secret exposed in a response.
//
// A long-lived provider credential served in a body or inline script is a direct
// leak. Matched on the fixed prefixes the major providers mint, which are specific
// enough that the match itself is the evidence.

fn first_http_text(responses) {
    for raw in responses {
        if http_response(raw) != () { return text(raw); }
    }
    ""
}

fn analyze(ctx, responses) {
    let body = first_http_text(responses);
    if body == "" { return []; }

    let kind = "";
    if re_is_match("AKIA[0-9A-Z]{16}", body) { kind = "an AWS access key"; }
    else if re_is_match("AIza[0-9A-Za-z_-]{35}", body) { kind = "a Google API key"; }
    else if re_is_match("xox[baprs]-[0-9A-Za-z-]{10,}", body) { kind = "a Slack token"; }
    else if re_is_match("ghp_[0-9A-Za-z]{36}", body) { kind = "a GitHub token"; }
    if kind == "" { return []; }

    [ #{
        severity: "high",
        summary: "A provider API key is exposed in the response",
        detail: "the response body carries " + kind + ", a credential that should never reach a client",
        references: [ #{ cwe: 312 } ],
    } ]
}
