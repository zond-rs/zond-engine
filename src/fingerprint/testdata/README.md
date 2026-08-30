# `src/fingerprint/testdata/`

Binary fixtures that a test cannot reasonably write inline, `include_bytes!`d
from the module that reads them.

The one file here, `selfsigned.der`, is a DER-encoded self-signed certificate.
It is read by `tls_summary.rs` and by the corpus tests in `corpus.rs`, which
both need a real certificate rather than a plausible-looking byte string:
summarising one exercises a parser, and a hand-made array would test the array.

This directory has no module of its own and does not want one. Nothing here is
Rust, and `include_bytes!` names a path rather than an item, so a `mod` would be
an empty file whose only job is to make the tree look uniform.

Anything added here should be small, should be read by exactly the module it
sits under, and should say in that module's test why a real artefact was needed.
