// JWT accepts the unsigned 'none' algorithm.
//
// A JSON Web Token served with a header alg of "none" carries no signature, so
// anyone can forge one the server will accept. The token is found in the gathered
// response, its header decoded from base64url, and the algorithm read.

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

    let header = json(text(b64url_decode(parts[0])));
    if type_of(header) != "map" { return []; }

    let alg = header["alg"];
    if alg == () { return []; }
    if alg.to_lower() != "none" { return []; }

    [ #{
        severity: "high",
        summary: "A JSON Web Token is served with the unsigned 'none' algorithm",
        detail: "the token header declares alg=none, so its payload is unsigned and can be forged",
        references: [ #{ cwe: 347 } ],
    } ]
}
