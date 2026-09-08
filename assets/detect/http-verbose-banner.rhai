// Server banner discloses software versions.
//
// Server, X-Powered-By and X-AspNet-Version name the software and, often, its
// exact version, handing an attacker a starting point for matching known
// vulnerabilities. Informational: disclosure, not a flaw in itself.

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
    if list != "" { list += "; "; }
    list + item
}

fn analyze(ctx, responses) {
    let r = first_http(responses);
    if r == () { return []; }
    let h = r.headers;

    let leaks = "";
    let server = hv(h, "server");
    if server != "" && re_is_match("[0-9]+\\.[0-9]", server) {
        leaks = add(leaks, "Server: " + server);
    }
    let xpb = hv(h, "x-powered-by");
    if xpb != "" { leaks = add(leaks, "X-Powered-By: " + xpb); }
    let xav = hv(h, "x-aspnet-version");
    if xav != "" { leaks = add(leaks, "X-AspNet-Version: " + xav); }
    if leaks == "" { return []; }

    [ #{
        severity: "info",
        summary: "Server response headers disclose software versions",
        detail: leaks,
        references: [ #{ cwe: 200 } ],
    } ]
}
