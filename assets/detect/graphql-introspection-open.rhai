// GraphQL introspection is exposed without authentication.
//
// A short introspection query is POSTed to a few conventional endpoints. A schema
// in the reply hands an attacker the full map of types, fields and arguments,
// which a production endpoint should not disclose.
//
// A timed-out exchange means the port is not answering POSTs at all, so the rest
// of the paths are skipped rather than waited on; a fast non-match just tries the
// next path.

fn try_speak(req) {
    let r = ();
    try { r = speak(req); } catch (e) { r = (); }
    r
}

fn analyze(ctx, responses) {
    let host = "" + ctx.addr;
    let query = "{\"query\":\"{__schema{queryType{name}}}\"}";
    let paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

    for path in paths {
        let req = http_request(#{
            method: "POST",
            path: path,
            host: host,
            headers: #{ "Content-Type": "application/json" },
            body: query,
        });
        let reply = try_speak(req);
        if reply == () { break; }
        if reply.len() == 0 { continue; }

        let r = http_response(reply);
        if type_of(r) != "map" { continue; }
        if r.status != 200 { continue; }
        if r.body.contains("__schema") || r.body.contains("queryType") {
            return [ #{
                severity: "medium",
                summary: "GraphQL introspection is exposed without authentication",
                detail: "POST " + path + " returned an introspection schema, disclosing the API's types and fields",
                references: [ #{ cwe: 200 } ],
            } ];
        }
    }
    []
}
