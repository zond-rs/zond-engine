// memcached UDP enables traffic amplification.
//
// A UDP 'stats' command is a few bytes; an exposed memcached answers with a much
// larger response, which an attacker reflects off a spoofed source for one of the
// largest amplification factors seen in the wild.

fn try_speak(req) {
    let r = ();
    try { r = speak(req); } catch (e) { r = (); }
    r
}

fn analyze(ctx, responses) {
    // memcached UDP frame (reqid, seq, n-datagrams, reserved) + "stats\r\n".
    let req = hex_decode("000100000001000073746174730d0a");
    let reply = try_speak(req);
    if reply == () { return []; }
    if reply.len() < 100 { return []; }

    let ratio = reply.len() / req.len();
    if ratio < 5 { return []; }

    [ #{
        severity: "medium",
        summary: "memcached answers UDP stats with an amplified response",
        detail: "the UDP stats reply is " + ratio + " times the request (" + reply.len() + " bytes), usable to reflect amplified traffic",
        references: [ #{ cwe: 406 } ],
    } ]
}
