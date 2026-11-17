Content corpus (synthetic fixtures; no real mail):
  hostile/      hostile.html (script, event handlers, remote and local references, CSS tricks),
                representative.html (an ordinary newsletter-style message) and style-escapes.html
                (CSS escapes that decode to markup, in sheets and attributes: MAILSANITIZE-2026-001)
  dark-mode/    23 dark-mode fixtures and their images (images/manifest.json lists sizes and hashes)
  text-fallback/textgen.py   `textgen.py fixtures DIR` writes the 34 text-fallback fixtures (several
                1-4 MiB stress documents) and expect.json; tools/gate.sh test adds them to the corpus
                test. Pure function of its arguments.
