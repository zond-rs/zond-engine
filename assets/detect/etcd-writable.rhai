// Unauthenticated write to etcd's v3 key-value API.
//
// etcd holds a cluster's secrets and is meant to require mutual TLS. A PUT that
// the v3 JSON gateway accepts with no client certificate is a write anyone can
// make. The canary key is deleted again in the same run.

fn try_speak(req) {
    let r = ();
    try { r = speak(req); } catch (e) { r = (); }
    r
}

fn analyze(ctx, responses) {
    let host = "" + ctx.addr;

    // key "zond-canary" and value "zond", base64 as the v3 API wants them.
    let put = http_request(#{
        method: "POST", path: "/v3/kv/put", host: host,
        headers: #{ "Content-Type": "application/json" },
        body: "{\"key\":\"em9uZC1jYW5hcnk=\",\"value\":\"em9uZA==\"}",
    });
    let reply = try_speak(put);
    if reply == () { return []; }

    let r = http_response(reply);
    if type_of(r) != "map" || r.status != 200 { return []; }
    if !r.body.contains("header") { return []; }

    // clean up: delete the canary key.
    let del = http_request(#{
        method: "POST", path: "/v3/kv/deleterange", host: host,
        headers: #{ "Content-Type": "application/json" },
        body: "{\"key\":\"em9uZC1jYW5hcnk=\"}",
    });
    try_speak(del);

    [ #{
        severity: "high",
        summary: "etcd accepted a write without a client certificate",
        detail: "a canary key was written through the v3 API with no client certificate and then deleted; etcd is meant to require mutual TLS",
        references: [ #{ cwe: 306 } ],
    } ]
}
