// Weak Content-Security-Policy.
//
// A CSP that is present but undermines itself. A missing CSP is the header-count
// check's job; this grades one that exists.
//
// The grading is per directive, because a CSP is not one string and a keyword does
// not mean the same thing in every part of it. Two readings follow from that, and
// both are the difference between this finding and a false one:
//
//   * `'unsafe-inline'` in `script-src` is cancelled by a nonce, a hash, or
//     `'strict-dynamic'` in the same directive. That is not a subtlety of the spec
//     to be generous about; it is how CSP Level 3 tells an author to deploy a
//     nonce policy. A browser that understands the nonce ignores `'unsafe-inline'`
//     outright, and it is written alongside deliberately so that a browser too old
//     to understand either still gets a working page. A check that reads the header
//     as one blob marks the recommended deployment as the weakness it exists to
//     fix, and the policies it accuses are the ones somebody did the work on.
//
//   * A wildcard is graded where it is found. `script-src *` is a policy that
//     permits any script from anywhere, which is most of what a CSP is for.
//     `img-src *` permits pictures, which is ordinary and which the substring
//     `-src *` cannot tell apart from the first.
//
// `style-src` keeps its own rung: inline style is a real weakness and a much
// narrower one than inline script, so it is reported rather than folded in at the
// same weight.
//
// The exposure is not read. A CSP is a mitigation the browser applies, and who can
// reach the server does not change what the policy says.

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
    if list != "" { list += ", "; }
    list + item
}

// `trim` mutates in place and yields unit, so trimming a value needs a name to
// mutate and the name handed back. Every string read out of the header goes
// through this.
fn trimmed(s) { s.trim(); s }

// The source list for `name`, or unit where the policy declares no such directive.
// A directive is `name source source ...`, the directives separated by `;`.
fn directive(csp, name) {
    for part in csp.split(';') {
        let text = trimmed(part);
        if text == "" { continue; }
        // The name is the first token; compare it whole, so `script-src-elem` is
        // not read as `script-src`.
        let space = text.index_of(' ');
        let head = if space < 0 { text } else { text.sub_string(0, space) };
        if head == name {
            return if space < 0 { "" } else { trimmed(text.sub_string(space + 1)) };
        }
    }
    ()
}

// The source list that governs `name`, falling back to `default-src` the way a
// browser does. Unit where neither is declared.
fn effective(csp, name) {
    let own = directive(csp, name);
    if own != () { return own; }
    directive(csp, "default-src")
}

// Whether a source list names a nonce, a hash, or `'strict-dynamic'`, any of which
// makes a supporting browser ignore `'unsafe-inline'` beside it.
fn nonce_governed(sources) {
    sources.contains("'nonce-")
        || sources.contains("'sha256-")
        || sources.contains("'sha384-")
        || sources.contains("'sha512-")
        || sources.contains("'strict-dynamic'")
}

// Whether a source list permits any origin. `*` as a source of its own, not the
// `*` inside a host pattern such as `*.example.com`, which is a named domain.
fn wildcard(sources) {
    for source in sources.split(' ') {
        if trimmed(source) == "*" { return true; }
    }
    false
}

fn analyze(ctx, responses) {
    let r = first_http(responses);
    if r == () { return []; }

    let csp = hv(r.headers, "content-security-policy").to_lower();
    if csp == "" { return []; }

    let weak = "";

    // Script: the directive a CSP is mostly written for.
    let script = effective(csp, "script-src");
    if script == () {
        // Neither `script-src` nor `default-src`: the policy governs no script at
        // all, whatever else it says.
        weak = add(weak, "no script-src or default-src");
    } else {
        if script.contains("'unsafe-inline'") && !nonce_governed(script) {
            weak = add(weak, "script-src 'unsafe-inline' with no nonce or hash");
        }
        // `'unsafe-eval'` is not cancelled by a nonce: it permits `eval` of strings
        // the nonce says nothing about.
        if script.contains("'unsafe-eval'") {
            weak = add(weak, "script-src 'unsafe-eval'");
        }
        if wildcard(script) {
            weak = add(weak, "script-src *");
        }
    }

    // Style: inline CSS is a real weakness and a narrower one than inline script.
    let style = effective(csp, "style-src");
    if style != () && style.contains("'unsafe-inline'") && !nonce_governed(style) {
        weak = add(weak, "style-src 'unsafe-inline'");
    }

    // A wildcard object or frame source is how a policy gets undone sideways.
    for name in ["object-src", "frame-src"] {
        let sources = effective(csp, name);
        if sources != () && wildcard(sources) {
            weak = add(weak, name + " *");
        }
    }

    if weak == "" { return []; }

    // Inline script with nothing holding it back, eval, or a script wildcard is
    // the policy failing at its main job. Anything else here is a policy that
    // works with a gap in it.
    let severity = if weak.contains("script-src") { "medium" } else { "low" };

    [ #{
        severity: severity,
        summary: "Content-Security-Policy weakens its own protection",
        detail: "weak directives: " + weak,
        references: [ #{ cwe: 693 } ],
    } ]
}
