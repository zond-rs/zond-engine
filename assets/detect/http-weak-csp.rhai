// Weak Content-Security-Policy.
//
// A CSP that is present but undermines itself: it allows inline or eval'd script,
// opens a fetch directive to any origin, or declares no script fallback at all. A
// missing CSP is the header-count check's job; this grades one that exists.

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

    let csp = hv(r.headers, "content-security-policy").to_lower();
    if csp == "" { return []; }

    let weak = "";
    if csp.contains("unsafe-inline") { weak = add(weak, "unsafe-inline"); }
    if csp.contains("unsafe-eval") { weak = add(weak, "unsafe-eval"); }
    if csp.contains("-src *") { weak = add(weak, "wildcard source"); }
    if !csp.contains("default-src") && !csp.contains("script-src") {
        weak = add(weak, "no script fallback");
    }
    if weak == "" { return []; }

    [ #{
        severity: "medium",
        summary: "Content-Security-Policy weakens its own protection",
        detail: "weak directives: " + weak,
        references: [ #{ cwe: 693 } ],
    } ]
}
