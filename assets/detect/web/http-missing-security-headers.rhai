// Missing HTTP security headers.
//
// A passive check over the response the scan already gathered: it counts how many
// of the baseline security headers a server omits and reports a finding whose
// severity rises with the count. It earns Tier 2 because the verdict is computed,
// several conditions folded into a count and the count into a severity, which a
// single-match flow cannot express.

fn analyze(ctx, responses) {
    if responses.len() == 0 {
        return [];
    }

    // Decode the gathered response and judge it case-insensitively.
    let response = text(responses[0]).to_lower();

    // Only grade something that actually answered as HTTP; a stray banner on the
    // port is not ours to score.
    if !response.contains("http/") {
        return [];
    }

    // A redirect carries none of the site's own headers: its whole job is to point
    // at the page that does, and that page is where a security header belongs. The
    // status line is the first line, so a 3xx there with a Location header means
    // this response is the redirector, not the site. Grading it reports the
    // redirector's posture as the site's, which is the false positive a plain
    // http-to-https hop on port 80 produces. Leave it to the probe that reaches
    // the target.
    let status_line = response;
    let line_end = response.index_of("\r\n");
    if line_end > 0 {
        status_line = response.sub_string(0, line_end);
    }
    let fields = status_line.split(' ');
    if fields.len() > 1 && fields[1].starts_with("30") && response.contains("location:") {
        return [];
    }

    let headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
    ];

    let count = 0;
    let missing = "";
    for header in headers {
        if !response.contains(header) {
            count += 1;
            if missing != "" {
                missing += ", ";
            }
            missing += header;
        }
    }

    if count == 0 {
        return [];
    }

    // Half or more of the baseline absent is a materially weaker posture than one
    // or two, so the severity follows the count rather than being fixed.
    let severity = if count >= 3 { "medium" } else { "low" };

    [ #{
        severity: severity,
        summary: "missing " + count + " of " + headers.len() + " HTTP security headers",
        detail: "missing: " + missing,
        references: [ #{ cwe: 693 } ],
    } ]
}
