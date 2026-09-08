// Redis reports an end-of-life version.
//
// An unauthenticated INFO returns the running version. A major version below the
// supported line no longer receives security fixes, so a known CVE in it stays
// open. Read only; if the server demands auth or does not answer, nothing is
// reported.

fn try_speak(req) {
    let r = ();
    try { r = speak(req); } catch (e) { r = (); }
    r
}

fn analyze(ctx, responses) {
    let reply = try_speak(bytes("INFO server\r\n"));
    if reply == () { return []; }

    let txt = text(reply);
    if !txt.contains("redis_version:") { return []; }

    let ver = re_capture("redis_version:([0-9]+\\.[0-9]+)", txt);
    if ver == "" { return []; }

    let major = re_capture("^([0-9]+)", ver);
    if major == "" { return []; }
    if parse_int(major) >= 6 { return []; }

    [ #{
        severity: "low",
        summary: "Redis reports an end-of-life version (" + ver + ")",
        detail: "redis_version " + ver + " is past its supported line and no longer receives security fixes",
        references: [ #{ cwe: 1104 } ],
    } ]
}
