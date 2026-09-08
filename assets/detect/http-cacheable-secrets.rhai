// Cookie set on a cacheable response.
//
// A response that both sets a cookie and is explicitly, publicly cacheable: a
// shared cache may store it and hand one user's cookie to the next. Only an
// explicit public directive counts, so a normal private page does not trip it.

fn first_http(responses) {
    for raw in responses {
        let r = http_response(raw);
        if r != () { return r; }
    }
    ()
}

fn hv(headers, name) {
    let v = headers[name];
    if v == () { "" } else { v }
}

fn analyze(ctx, responses) {
    let r = first_http(responses);
    if r == () { return []; }
    if r.status != 200 { return []; }

    let sc = hv(r.headers, "set-cookie");
    if sc == "" { return []; }

    let cc = hv(r.headers, "cache-control").to_lower();
    if !cc.contains("public") { return []; }
    if cc.contains("no-store") || cc.contains("private") { return []; }

    [ #{
        severity: "low",
        summary: "A cookie is set on a publicly cacheable response",
        detail: "Cache-Control: " + cc,
        references: [ #{ cwe: 525 } ],
    } ]
}
