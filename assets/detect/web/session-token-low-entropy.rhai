// Session cookie value carries weak entropy.
//
// A session identifier a client holds must be hard to guess. This reads the value
// of a session-named Set-Cookie and estimates its entropy as length times the
// log2 of its distinct characters, an optimistic bound. Flagged only when even
// that best case falls short, so a genuinely random token never trips it.
//
// A cookie being withdrawn is not a session. A logout overwrites the value with a
// placeholder such as `deleted` or `0` and tells the browser to drop it, with
// `Max-Age` zero or below or an `Expires` already past. There is no token there to
// guess, so such a cookie is skipped. An expiry is past when it is no later than
// the response's own `Date`, or, with no `Date`, when it falls before 2000, where
// every framework's withdrawal date does.

fn trimmed(s) { s.trim(); s }

// Whether a cookie name looks like a session identifier. `sid` must end the name:
// as a bare substring it matches ordinary words such as `residency`.
fn is_session(name) {
    name.contains("sess") || name.ends_with("sid") || name.contains("token")
        || name.contains("auth") || name.contains("aspnet")
}

// An HTTP date as a number that sorts as the date does, yyyymmddhhmmss, or -1
// when `s` holds none. Reads the IMF-fixdate and RFC 850 forms.
fn date_key(s) {
    let found = re_find("[0-9]{1,2}[ -][A-Za-z]{3}[ -][0-9]{2,4} [0-9]{2}:[0-9]{2}:[0-9]{2}", s);
    if found == "" { return -1; }
    found.replace("-", " ");
    let parts = found.split(" ");
    let month = "janfebmaraprmayjunjulaugsepoctnovdec".index_of(parts[1].to_lower());
    if month < 0 || month % 3 != 0 { return -1; }
    let year = parse_int(parts[2]);
    if year < 70 { year += 2000; } else if year < 100 { year += 1900; }
    let time = parts[3].split(":");
    let key = year * 100 + month / 3 + 1;
    key = key * 100 + parse_int(parts[0]);
    key = key * 100 + parse_int(time[0]);
    key = key * 100 + parse_int(time[1]);
    key * 100 + parse_int(time[2])
}

fn analyze(ctx, responses) {
    for raw in responses {
        let response = http_response(raw);
        if response == () { continue; }

        let date = response.headers["date"];
        let now = if date == () { -1 } else { date_key(date) };

        let lines = text(raw).split('\n');
        for line in lines {
            let header = trimmed(line);
            if !header.to_lower().starts_with("set-cookie:") { continue; }

            // `name=value` first, then the attributes, all `;`-separated.
            let parts = trimmed(header.sub_string(11)).split(';');
            let pair = trimmed(parts[0]);
            let eq = pair.index_of('=');
            if eq < 1 { continue; }
            let name = trimmed(pair.sub_string(0, eq)).to_lower();
            if !is_session(name) { continue; }
            let val = trimmed(pair.sub_string(eq + 1));

            let lower = val.to_lower();
            let withdrawn = lower == "" || lower == "deleted" || lower == "0"
                || lower == "null" || lower == "none";
            for index in 1..parts.len() {
                let attribute = trimmed(parts[index]).to_lower();
                let split = attribute.index_of('=');
                if split < 0 { continue; }
                let key = trimmed(attribute.sub_string(0, split));
                let setting = trimmed(attribute.sub_string(split + 1));
                if key == "max-age" && re_is_match("^-?[0-9]+$", setting) && parse_int(setting) <= 0 {
                    withdrawn = true;
                }
                if key == "expires" {
                    let expires = date_key(setting);
                    if expires >= 0 && (if now >= 0 { expires <= now } else { expires < 20000101000000 }) {
                        withdrawn = true;
                    }
                }
            }
            if withdrawn { continue; }

            let n = val.len();
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
