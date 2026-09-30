// Session cookie set without security flags.
//
// A `Set-Cookie` whose name looks like a session identifier and which omits
// `HttpOnly`, leaving it readable by script, or `Secure`, leaving it sent in the
// clear. The raw header lines are read rather than the folded map, since a cookie's
// `Expires` date carries the comma the folding would split on.
//
// Three things this is careful about, each of them a way the check reported
// something that was not there:
//
//   * **It says which flag is missing.** One fixed sentence naming both is wrong
//     on the common case, and wrong in the direction a reader notices: a cookie
//     that *is* `HttpOnly` and merely lacks `Secure` was reported as having
//     neither, on the one line a console shows.
//
//   * **A flag is an attribute, not a substring.** `Set-Cookie` attributes are
//     `;`-separated, so each is compared whole. Searching the line for `secure`
//     finds it in a cookie *named* `secure_session`, and reads a cookie with no
//     flags at all as flagged.
//
//   * **A cookie being deleted is not a session.** A logout sets the name to an
//     empty value with `Max-Age=0` or an expiry in the past, and the browser drops
//     it. There is nothing there to steal, and flagging it reports the sign-out
//     path as a weakness.
//
// The severity follows which flag is absent rather than being fixed. Missing
// `HttpOnly` means any script on the page can read the session, which is what turns
// an injection into a stolen account. Missing `Secure` alone is a rung below that:
// on a plaintext origin the cookie is already in the clear and a browser will not
// honour `Secure` over it anyway, so what the flag would protect against is the
// origin being plaintext; on a TLS origin it is the cookie leaking if the site is
// ever reached without it.
//
// The exposure is not read. Who can reach the server does not change whether a
// script on its own page can read the cookie.

fn trimmed(s) { s.trim(); s }

fn add(list, item) {
    if list != "" { list += ", "; }
    list + item
}

// Whether a cookie name looks like a session identifier.
//
// `sid` is required at the end of the name rather than anywhere in it: as a bare
// substring it matches ordinary words, and a cookie called `residency` is not a
// session. Everything else here is distinctive enough to match loosely.
fn session_name(lower) {
    lower.contains("sess")
        || lower.ends_with("sid")
        || lower.contains("token")
        || lower.contains("auth")
        || lower.contains("jwt")
}

fn analyze(ctx, responses) {
    for raw in responses {
        if http_response(raw) == () { continue; }

        let lines = text(raw).split('\n');
        let no_httponly = "";
        let no_secure = "";
        let missing_httponly = false;
        let missing_secure = false;

        for line in lines {
            // Named `header` rather than `text`, which is the name of the builtin
            // that decoded the response above.
            let header = trimmed(line);
            if !header.to_lower().starts_with("set-cookie:") { continue; }

            // `name=value` first, then the attributes, all `;`-separated.
            let parts = trimmed(header.sub_string(11)).split(';');
            if parts.len() == 0 { continue; }

            let pair = trimmed(parts[0]);
            let eq = pair.index_of('=');
            let name = if eq < 0 { pair } else { trimmed(pair.sub_string(0, eq)) };
            let value = if eq < 0 { "" } else { trimmed(pair.sub_string(eq + 1)) };
            if !session_name(name.to_lower()) { continue; }

            // Each attribute compared whole. `Max-Age` and `Expires` carry a value,
            // so they are read up to their `=`.
            let has_httponly = false;
            let has_secure = false;
            let clearing = value == "" || value == "deleted";
            for index in 1..parts.len() {
                let attribute = trimmed(parts[index]).to_lower();
                let split = attribute.index_of('=');
                let key = if split < 0 { attribute } else { trimmed(attribute.sub_string(0, split)) };
                let setting = if split < 0 { "" } else { trimmed(attribute.sub_string(split + 1)) };
                if key == "httponly" { has_httponly = true; }
                if key == "secure" { has_secure = true; }
                // `Max-Age=0`, and the 1970 expiry every framework spells the same
                // way, are the two ways a cookie is withdrawn.
                if key == "max-age" && setting == "0" { clearing = true; }
                if key == "expires" && setting.contains("1970") { clearing = true; }
            }

            // Nothing to protect in a cookie the browser is being told to drop.
            if clearing { continue; }

            if !has_httponly {
                missing_httponly = true;
                no_httponly = add(no_httponly, name);
            }
            if !has_secure {
                missing_secure = true;
                no_secure = add(no_secure, name);
            }
        }

        if !missing_httponly && !missing_secure { return []; }

        // The summary names the flag that is actually absent, and the severity
        // follows it: script access to the session is the material one.
        let summary = if missing_httponly && missing_secure {
            "A session cookie is set without HttpOnly or Secure"
        } else if missing_httponly {
            "A session cookie is set without HttpOnly"
        } else {
            "A session cookie is set without Secure"
        };
        let severity = if missing_httponly { "medium" } else { "low" };

        let detail = "";
        if no_httponly != "" { detail = add(detail, "no HttpOnly: " + no_httponly); }
        if no_secure != "" { detail = add(detail, "no Secure: " + no_secure); }

        return [ #{
            severity: severity,
            summary: summary,
            detail: detail,
            references: [ #{ cwe: 1004 } ],
        } ];
    }
    []
}
