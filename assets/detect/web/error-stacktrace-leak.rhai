// Error response leaked a stack trace.
//
// A response body carrying a framework stack trace gives away internal paths,
// class names and library versions. Matched against the distinctive shape each
// runtime's trace has, not a loose keyword, so ordinary prose does not trip it.

fn first_http(responses) {
    for raw in responses {
        let r = http_response(raw);
        if r != () { return r; }
    }
    ()
}

fn analyze(ctx, responses) {
    let r = first_http(responses);
    if r == () { return []; }

    let body = r.body.to_lower();
    if body == "" { return []; }

    let lang = "";
    if re_is_match("\\bat [\\w.$]+\\([\\w]+\\.java:[0-9]+\\)", body) {
        lang = "Java";
    } else if body.contains("traceback (most recent call last)") {
        lang = "Python";
    } else if body.contains("stack trace:") && body.contains(".php") {
        lang = "PHP";
    } else if re_is_match("\\.cs:line [0-9]+", body) {
        lang = ".NET";
    }
    if lang == "" { return []; }

    [ #{
        severity: "medium",
        summary: "An error response leaked a " + lang + " stack trace",
        detail: "a " + lang + " stack trace was served in the body, disclosing internal paths and class names",
        references: [ #{ cwe: 209 } ],
    } ]
}
