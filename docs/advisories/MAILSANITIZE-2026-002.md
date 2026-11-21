# MAILSANITIZE-2026-002: CSS image sources that bypass the URL check

| | |
|---|---|
| Affected | 0.1.0 to 0.2.2 |
| Fixed | 0.2.3 |
| Severity | Medium: sender-chosen image bytes reach the renderer's image decoders, whatever `Images` says |
| Found | 2026-11-20, in a security review of a consumer |

## Impact

The output contract says that no image source in the output can reach anything but the document's own resources, and
that `Images::Off` maps every image to the placeholder. In CSS that held only for `url()` values. A sender could write an
image source the URL check never saw, for example

```html
<p style='background-image:image-set("data:image/webp;base64,…" 1x)'>
<p style='--a:image-set("data:image/gif;base64,…" 1x);background-image:var(--a)'>
```

and the declaration was printed unchanged. A consumer that renders the output behind a Content-Security-Policy without
`data:` in `img-src` is not affected; one that allows `data:` images (for the inline images of 0.1.x, say) lets the
renderer decode the sender's own WebP, GIF, AVIF, BMP, ICO or SVG bytes, with `Images::Off` set or not.

## Cause

- lightningcss's visitor skips the images inside `image-set()` (its `skip_type`), so even `image-set(url(data:…))` was
  never passed to the URL check, and the sources of an image set may be plain strings.
- Values lightningcss does not parse (custom properties, `var()`, unknown functions) are kept as token lists, with an
  image source as a string or raw URL token. The URL check visits only parsed `url()` values.

## Fix

- Any declaration holding a parsed `image-set()` is dropped.
- Every custom property (`--x`) is dropped, and so is every declaration whose unparsed value holds a `var()` or `env()`
  (substituted after sanitizing), a string or raw URL token, or an image function: `image-set`, `cross-fade`, `image`,
  `element`, `paint`, `-webkit-canvas` and their prefixed forms.
- The `sanitize` fuzz target checks every `<style>` text and `style` attribute too: outside strings, every `url(` names
  a resource reference, and there is no image function, `var()`, `env()` or custom property. A corpus seed holds the
  examples above.

## Workarounds

Upgrade to 0.2.3. Until then, render the document behind a Content-Security-Policy whose `img-src` allows only the
consumer's own resource scheme (no `data:`).
