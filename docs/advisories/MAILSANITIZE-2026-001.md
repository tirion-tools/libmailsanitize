# MAILSANITIZE-2026-001: allowlist bypass through CSS escapes in `<style>`

| | |
|---|---|
| Affected | 0.1.0, 0.1.1 |
| Fixed | 0.1.2 |
| Severity | High: a full bypass of the tag and attribute allowlist |
| Found | 2026-11-17, by the `sanitize` fuzz target |

## Impact

A crafted `<style>` element could close itself in the sanitized document, so any markup after it reached the output
without passing the allowlist: `<script>`, `<iframe>`, `<object>`, `<embed>`, `<meta http-equiv="refresh">`, `<base>`,
forms, `on*` attributes, `javascript:` links, remote images and unfiltered `style` attributes. Every theme was affected.

A consumer that renders the output with JavaScript enabled is open to cross-site scripting. With JavaScript disabled, a
strict Content-Security-Policy and no network for the document, the injected markup cannot run script or fetch anything.
It can still change what the message looks like, without the CSS allowlist: for example fixed overlays and form
controls.

## Cause

Every `<style>` sheet is parsed and re-printed by lightningcss, and the printed sheet is put back into the document as raw
HTML text. lightningcss decodes CSS escapes and prints the characters they stand for. In strings, URLs and unparsed
values these come out as they are. So

```html
<style>a{font-family:"\3c/style\3e\3cscript\3e alert(1)\3c/script\3e"}</style>
```

came out as

```html
<style>a{font-family:"</style><script>alert(1)</script>"}</style>
```

HTML parsers end a `<style>` element at the first `</style`, whatever the CSS around it. The rest was parsed as markup.
The input itself holds no `</style` inside the sheet, so the allowlist pass, which parses the input, never saw that markup.

The fuzz input that found the bug is a milder form of the same cause: an unclosed `<style>` takes in the rest of the part,
and lightningcss prints `<script>` from it as CSS tokens. That is text inside the sheet, not an element.

## Fix

- Every sheet and `style` attribute that lightningcss prints is made inert as HTML before it is written into the
  document. No `<` in printed CSS is followed by a letter, `/`, `!` or `?`. In strings and identifiers it becomes the
  CSS escape `\3c `; a bare `<`, as in media ranges, gets a space after it. The CSS means the same.
- An output check, independent of the escaping. The finished document is parsed again with html5ever and must hold the
  sanitizer's frame around exactly the allowlisted elements, with no `</` in any `<style>` text. A document that fails
  is replaced by the plain-text fallback, its `<body>` marked `data-gx-fallback="text"`.
- The fuzz target parses every output with html5ever's own tree and asserts the output contract on it: no `</` in a
  `<style>` text, no script, frame, plugin, form, `<base>`, `<link>`, SVG or MathML element, no `<meta http-equiv>`, no
  `on*` attribute, no `javascript:` URL, and no fallback.

## Workarounds

Upgrade to 0.1.2. Until then, render the document without JavaScript and without network, behind a CSP with
`script-src 'none'` and `default-src 'none'`. That contains the injected markup but does not remove it.
