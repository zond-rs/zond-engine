// Session cookie value carries weak entropy.
//
// A session identifier a client holds must be hard to guess. This reads the value
// of a session-named Set-Cookie and estimates its entropy as length times the
// log2 of its distinct characters, an optimistic bound. Flagged only when even
// that best case falls short, so a genuinely random token never trips it.

fn is_session(name) {
    name.contains("sess") || name.contains("sid") || name.contains("token")
        || name.contains("auth") || name.contains("jsessionid")
        || name.contains("phpsessid") || name.contains("aspnet")
}

fn analyze(ctx, responses) {
    for raw in responses {
        if http_response(raw) == () { continue; }

        let lines = text(raw).split('\n');
        for line in lines {
            let l = line.to_lower();
            if !l.starts_with("set-cookie:") { continue; }

            let after = l.sub_string(11);
            let eq = after.index_of("=");
            if eq < 1 { continue; }
            let name = after.sub_string(0, eq);
            name.trim();
            if !is_session(name) { continue; }

            let rest = after.sub_string(eq + 1);
            let semi = rest.index_of(";");
            let val = if semi >= 0 { rest.sub_string(0, semi) } else { rest };
            val.trim();

            let n = val.len();
            if n == 0 { continue; }

            let seen = #{};
            let i = 0;
            while i < n {
                seen[val.sub_string(i, 1)] = true;
                i += 1;
            }
            let distinct = seen.len();

            let bits = 0.0;
            if distinct > 1 {
                bits = n.to_float() * (distinct.to_float().ln() / (2.0).ln());
            }
            if bits < 40.0 {
                return [ #{
                    severity: "medium",
                    summary: "A session cookie value is weak enough to guess",
                    detail: "cookie '" + name + "' holds about " + (bits.to_int()) + " bits over " + n + " characters",
                    references: [ #{ cwe: 330 } ],
                } ];
            }
        }
        return [];
    }
    []
}
