// ETag discloses a filesystem inode.
//
// Apache's default FileETag can encode inode, size and mtime as three hex fields.
// The inode leaks a detail of the server's filesystem and lets a resource be
// fingerprinted across virtual hosts. A two-field size-mtime ETag is not flagged.

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

    let etag = hv(r.headers, "etag").to_lower();
    if etag == "" { return []; }
    if !re_is_match("^\"?[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\"?$", etag) { return []; }

    [ #{
        severity: "low",
        summary: "ETag exposes a filesystem inode",
        detail: "ETag: " + etag,
        references: [ #{ cwe: 200 } ],
    } ]
}
