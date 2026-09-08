// JWT issued without an expiry claim.
//
// A JSON Web Token whose payload carries no exp claim never expires on its own, so
// a leaked or stolen one stays valid indefinitely. The token is found in the
// gathered response and its payload decoded from base64url.

fn first_http_text(responses) {
    for raw in responses {
        if http_response(raw) != () { return text(raw); }
    }
    ""
}

fn b64url_decode(s) {
    s.replace("-", "+");
    s.replace("_", "/");
    let rem = s.len() % 4;
    if rem == 2 { s += "=="; } else if rem == 3 { s += "="; }
    b64_decode(s)
}

fn analyze(ctx, responses) {
    let body = first_http_text(responses);
    if body == "" { return []; }

    let jwt = re_find("eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]*", body);
    if jwt == "" { return []; }

    let parts = jwt.split('.');
    if parts.len() < 2 { return []; }

    let payload = json(text(b64url_decode(parts[1])));
    if type_of(payload) != "map" { return []; }
    if payload["exp"] != () { return []; }

    [ #{
        severity: "low",
        summary: "A JSON Web Token is issued without an expiry (exp) claim",
        detail: "the token payload has no exp claim, so it does not expire and a leaked copy stays valid",
        references: [ #{ cwe: 613 } ],
    } ]
}
