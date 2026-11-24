Content corpus (synthetic fixtures; no real mail):
  hostile/      hostile.html (script, event handlers, remote and local references, CSS tricks),
                representative.html (an ordinary newsletter-style message) and style-escapes.html
                (CSS escapes that decode to markup, in sheets and attributes: MAILSANITIZE-2026-001)
  dark-mode/    25 dark-mode fixtures and their images (images/manifest.json lists sizes and hashes);
                24-link-text-layout.html is an HTML-only notice whose link texts span source lines;
                25-flattened-nested-rule.html has newsletter cells whose style attributes carry an
                SCSS nested rule (&::before{...}) flattened with its braces lost
  text-fallback/textgen.py   `textgen.py fixtures DIR` writes the 34 text-fallback fixtures (several
                1-4 MiB stress documents) and expect.json; tools/gate.sh test adds them to the corpus
                test. Pure function of its arguments.
