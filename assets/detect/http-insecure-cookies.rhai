// Session cookie set without security flags.
//
// A Set-Cookie whose name looks like a session identifier but which omits
// HttpOnly or Secure, leaving it reachable by script or sent in the clear. The
// raw header lines are read rather than the folded map, since a cookie's Expires
// date carries the comma the folding would split on.

fn trimmed(s) { s.trim(); s }

fn add(list, item) {
    if list != "" { list += ", "; }
    list + item
}

fn analyze(ctx, responses) {
    for raw in responses {
        if http_response(raw) == () { continue; }

        let lines = text(raw).split('\n');
        let hits = "";
        for line in lines {
            let l = line.to_lower();
            if !l.starts_with("set-cookie:") { continue; }

            let after = trimmed(l.sub_string(11));
            let eq = after.index_of("=");
            let name = if eq > 0 { after.sub_string(0, eq) } else { after };

            let is_session = name.contains("sess") || name.contains("sid")
                || name.contains("token") || name.contains("auth")
                || name.contains("jsessionid") || name.contains("phpsessid")
                || name.contains("aspnet");
            if !is_session { continue; }

            let missing = "";
            if !l.contains("httponly") { missing = add(missing, "HttpOnly"); }
            if !l.contains("secure") { missing = add(missing, "Secure"); }
            if missing != "" {
                hits = add(hits, name + " missing " + missing);
            }
        }

        if hits != "" {
            return [ #{
                severity: "medium",
                summary: "A session cookie is set without HttpOnly or Secure",
                detail: hits,
                references: [ #{ cwe: 1004 } ],
            } ];
        }
        return [];
    }
    []
}
