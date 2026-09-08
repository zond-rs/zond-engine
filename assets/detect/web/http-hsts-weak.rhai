// Weak HTTP Strict-Transport-Security.
//
// HSTS is present but gives less than it should: a max-age under six months, or
// no includeSubDomains. A missing header is the header-count check's job.

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

fn add(list, item) {
    if list != "" { list += ", "; }
    list + item
}

fn analyze(ctx, responses) {
    let r = first_http(responses);
    if r == () { return []; }

    let hsts = hv(r.headers, "strict-transport-security").to_lower();
    if hsts == "" { return []; }

    let weak = "";
    let age = re_capture("max-age=\"?(\\d+)", hsts);
    if age != "" && parse_int(age) < 15552000 { weak = add(weak, "max-age under 180 days"); }
    if !hsts.contains("includesubdomains") { weak = add(weak, "no includeSubDomains"); }
    if weak == "" { return []; }

    [ #{
        severity: "low",
        summary: "HTTP Strict-Transport-Security is weaker than it should be",
        detail: "weak: " + weak + " (" + hsts + ")",
        references: [ #{ cwe: 319 } ],
    } ]
}
