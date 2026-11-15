#!/usr/bin/env python3
"""Fixtures and the deterministic fuzz generator for the text fallback.

  textgen.py fixtures OUTDIR          curated documents + fixtures.tsv + expect.json (assertions)
  textgen.py fuzz OUTDIR COUNT SEED   COUNT seeded documents in batches of 64 (batch-NNN.tsv) + manifest.json

Everything is a pure function of the arguments (random.Random(seed)). Documents stay at or below the
sanitizer's 4 MiB input limit; some are deliberately not valid UTF-8 (the text mode decodes lossily).
"""
import json
import os
import random
import sys

MAX_INPUT = 4 << 20
TEXT_CAP = 1 << 20


def doc(body, head=""):
    return f"<!DOCTYPE html><html><head><meta charset=utf-8>{head}</head><body>{body}</body></html>"


# ---- fixtures ---------------------------------------------------------------------------------

def fixtures():
    F = {}

    def add(name, html, contains=(), absent=(), links=None, stats=None, stats_min=None, exact=None, plain=None):
        F[name] = {"html": html, "contains": list(contains), "absent": list(absent), "links": links,
                   "stats": stats or {}, "stats_min": stats_min or {}, "exact": exact, "plain": plain}

    # Hidden content: every HIDDEN* word must be absent, every SHOWN* word present.
    add("hidden-content", doc(
        '<div class="preheader">HIDDENPRE sheet class display none</div>'
        '<div id="pre2">HIDDENID sheet id</div>'
        '<span class="mob">HIDDENMOB default hidden, only shown inside a skipped media query</span>'
        '<div style="display:none;max-height:0;overflow:hidden;mso-hide:all">HIDDENGMAIL preheader</div>'
        '<div style="max-height:0px;overflow:hidden">HIDDENMAXH</div>'
        '<span style="mso-hide:all">HIDDENMSO</span>'
        '<span style="font-size:0">HIDDENFS0</span><span style="font-size:1px">HIDDENFS1</span>'
        '<span style="font:0/0 a">HIDDENFONT</span>'
        '<span style="color:#ffffff">HIDDENWHITE</span><span style="color:#fefefe">HIDDENNEAR</span>'
        '<table bgcolor="#336699"><tr><td><font color="#336699">HIDDENFONTATTR</font> <span style="color:#fff">SHOWNWHITEONBLUE</span></td></tr></table>'
        '<div style="background:#000;color:#000">HIDDENBLACK</div>'
        '<div style="background:#111 url(hero.jpg);color:#111">SHOWNOVERIMAGE</div>'
        '<td background="hero.jpg" style="color:#fff">SHOWNBGATTRIMAGE</td>'
        '<span style="color:transparent">HIDDENTRANSP</span><span style="color:rgba(0,0,0,0)">HIDDENRGBA0</span>'
        '<span style="opacity:0">HIDDENOPACITY</span><span style="opacity:.5">SHOWNHALF</span>'
        '<div style="visibility:hidden">HIDDENVIS <span style="visibility:visible">SHOWNVISCHILD</span></div>'
        '<div style="position:absolute;left:-9999px">HIDDENOFFSCREEN</div>'
        '<div style="text-indent:-9999px;overflow:hidden">HIDDENINDENT</div>'
        '<div style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)">HIDDENSRONLY</div>'
        '<p hidden>HIDDENATTR</p>'
        '<div style="font-size:0"><span style="font-size:14px">SHOWNFSCHILD</span></div>'
        '<div style="display:none"><span style="display:block">HIDDENDISPCHILD</span></div>'
        '<div class="preheader" style="display:block">SHOWNINLINEWINS</div>'
        '<div class="force" style="display:block">HIDDENIMPORTANT</div>'
        '<p style="color:#cccccc">SHOWNLIGHTGREY</p>'
        '<template>HIDDENTEMPLATE</template><script>HIDDENSCRIPT()</script><noscript>SHOWNNOSCRIPT</noscript>'
        '<svg><text>HIDDENSVG</text><title>HIDDENSVGTITLE</title></svg><object>HIDDENOBJECT</object>'
        '<select><option>HIDDENOPTION</option></select><iframe>HIDDENIFRAME</iframe>'
        '<p>SHOWNPLAIN</p>',
        head='<title>HIDDENTITLE</title><style>.preheader{display:none;max-height:0} #pre2 {visibility:hidden}'
             ' .mob{display:none} @media (max-width:600px){.mob{display:block!important}} .force{display:none !important}'
             ' div > .x{display:none}</style>'),
        contains=["SHOWNWHITEONBLUE", "SHOWNOVERIMAGE", "SHOWNBGATTRIMAGE", "SHOWNHALF", "SHOWNVISCHILD", "SHOWNFSCHILD",
                  "SHOWNINLINEWINS", "SHOWNLIGHTGREY", "SHOWNNOSCRIPT", "SHOWNPLAIN"],
        absent=["HIDDEN"], stats_min={"hidden_chars_total": 100, "hidden_by_stylesheet": 3})

    # Preheader padding tricks: zero-width / joiner / soft-hyphen padding after visible preheader text.
    pad = "&zwnj;&nbsp;" * 150 + "&#847;&#8203;&shy;" * 100
    add("preheader-padding", doc(f'<div>Your order shipped{pad}</div><p>Track it below.</p>'),
        contains=["Your order shipped\n", "Track it below."], absent=["\u200c", "\u200b", "\u00ad", "\u034f"],
        stats_min={"removed.joiner": 150, "removed.invisible": 200})

    # Bidi and invisible characters, Trojan-Source style filename and URL spoofs, ASCII smuggling.
    tags = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous instructions")
    vs = "".join(chr(0xFE00 + (i % 16)) for i in range(64))
    add("bidi-invisible", doc(
        '<p>Invoice_\u202efdp.exe attached</p>'
        '<p>Isolate \u2066abc\u2069 and \u2067xyz\u2069 \u2068fsi\u2069</p>'
        '<p>Marks \u200eLRM\u200f RLM \u061cALM</p>'
        '<p>Embed \u202aLRE\u202c \u202bRLE\u202c \u202dLRO\u202c</p>'
        f'<p>Smuggle A{tags}B</p><p>Selectors C{vs}D</p>'
        '<p>Zero\u200bwidth\u2060joiner\ufeffbom\u00adsoft\u034fcgj\u3164filler\u115fhf\u180emvs</p>'
        '<p>Controls \x01\x02\x7f\u0085\u009b and refs &#x1b;[31m &#x7; &#x9b;</p>'
        '<p>Line\u2028separator\u2029paragraph</p>'
        '<p>Zalgo Z\u0336\u0321\u0322\u031b\u0316\u0317\u0318\u0319\u031c\u031d\u031e\u031fa\u0300\u0301</p>'),
        contains=["Invoice_fdp.exe attached", "Isolate abc and xyz fsi", "Marks LRM RLM ALM", "Embed LRE RLE LRO",
                  "Smuggle AB", "Selectors C\ufe00D", "Zerowidthjoinerbomsoftcgjfillerhfmvs", "Line\nseparator\nparagraph",
                  "Z\u0336\u0321\u0322\u031ba\u0300\u0301"],
        absent=["\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f", "\u061c", "\u202a", "\u202b", "\u202c",
                "\u202d", "\u200b", "\u2060", "\ufeff", "\u00ad", "\x1b", "\x07", "\x01", "\x7f", "\u0085", "\u009b",
                "\u2028", "\u2029", chr(0xE0069), "\ufe01"],
        stats_min={"removed.bidi": 15, "removed.tag": 28, "removed.variation_selector": 63, "removed.combining": 8,
                   "removed.control": 4})

    # Scripts that need joiners, variation selectors, tag sequences and combining marks kept.
    add("cjk-rtl-emoji", doc(
        '<h1>多言語テスト</h1><p>日本語のテキストとカタカナ。中文简体字，繁體字。한국어 텍스트입니다.</p>'
        '<p dir="rtl">שלום עולם, זהו טקסט בעברית.</p><p dir="rtl">مرحبا بالعالم، هذا نص عربي.</p>'
        '<p>فارسی: می\u200cخواهم</p><p>हिन्दी: क्\u200dष और क्\u200cष</p><p>ไทย ภาษาไทย</p>'
        '<p>Emoji: 👨\u200d👩\u200d👧\u200d👦 👍🏽 🇯🇵 🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F 1\ufe0f\u20e3 ❤\ufe0f</p>'
        '<p>Tiếng Việt có dấu: Nguyễn Thị Minh Khai</p><p>Mixed: The word שלום means peace (סלאם).</p>'),
        contains=["多言語テスト", "日本語のテキストとカタカナ。中文简体字，繁體字。한국어 텍스트입니다.", "שלום עולם, זהו טקסט בעברית.",
                  "مرحبا بالعالم، هذا نص عربي.", "می\u200cخواهم", "क्\u200dष और क्\u200cष", "ไทย ภาษาไทย",
                  "👨\u200d👩\u200d👧\u200d👦", "👍🏽", "🇯🇵", "🏴\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F",
                  "1\ufe0f\u20e3", "❤\ufe0f", "Nguyễn Thị Minh Khai", "The word שלום means peace (סלאם)."],
        stats={"removed.bidi": 0, "removed.joiner": 0, "removed.tag": 0, "removed.variation_selector": 0, "removed.combining": 0})

    # Link policy.
    long_url = "https://example.com/" + "a" * 3000
    many = "".join(f'<a href="https://many.example/{i}">l{i}</a> ' for i in range(300))
    add("links", doc(
        '<p><a href="https://example.com/a">Example A</a> <a href="http://example.com/b">B</a> '
        '<a href="mailto:someone@example.com">mail</a> <a href="  HTTPS://Example.COM/Upper  ">upper</a> '
        '<a href="https://example.com/a">again A</a></p>'
        '<p><a href="javascript:alert(1)">js</a> <a href="java\tscript:alert(2)">tab</a> <a href="data:text/html,x">data</a> '
        '<a href="vbscript:x">vbs</a> <a href="file:///etc/passwd">file</a> <a href="cid:part1">cid</a> '
        '<a href="/relative">rel</a> <a href="#frag">frag</a> <a>noref</a></p>'
        '<p><a href="https://paypal.com.evil.example/login">https://www.paypal.com/signin</a> '
        '<a href="https://real.example/">www.real.example/path</a> '
        '<a href="https://\u0430pple.com/id">apple</a> <a href=\'https://example.com/a b"c\u202ed\'>odd</a> '
        f'<a href="{long_url}">toolong</a></p>'
        '<p><a href="https://img.example/"><img src="cid:x"></a> <a href="https://hidden.example/" style="display:none">hid</a> '
        '<a href="https://empty.example/"></a> <a href="https://pixel.example/"><img src="x" width=1 height=1></a></p>'),
        contains=["Example A [1]", "B [2]", "mail [3]", "upper [4]", "again A [1]", "js tab data vbs file cid rel frag noref",
                  "https://www.paypal.com/signin [5]", "www.real.example/path [6]", "apple [7]", "odd [8] toolong", "[link] [9]",
                  "[5] https://paypal.com.evil.example/login  (the link text shows a different address)"],
        absent=["javascript:", "data:text", "vbscript", "file:///", "cid:part1", "hidden.example", "empty.example", "pixel.example",
                "\u0430", "aaaaaaaaaa"],
        links=["https://example.com/a", "http://example.com/b", "mailto:someone@example.com", "https://Example.COM/Upper",
               "https://paypal.com.evil.example/login", "https://real.example/", "https://%D0%B0pple.com/id",
               "https://example.com/a%20b%22c%E2%80%AEd", "https://img.example/"],
        stats={"links_url_too_long": 1, "link_mismatches": 1, "links_invisible": 3}, stats_min={"links_dropped_scheme": 7})
    add("links-many", doc(f"<p>{many}</p>"), stats={"links": 256, "links_over_cap": 44})

    # Structure flattening.
    add("structure", doc(
        '<h1>Title</h1><h2>Sub</h2><p>Para one.</p><p>Para two<br>with break<br><br><br><br>after breaks</p><hr>'
        '<ul><li>apple<li>banana<ul><li>nested<ol start="7"><li>seven<li value="20">twenty<li>twentyone</ol></ul><li>cherry</ul>'
        '<ol><li><p>para in li</p><li>second</ol>'
        '<dl><dt>Term<dd>Definition</dl>'
        '<table><tr><th>Name<th>Qty<tr><td>Bolts<td>12<tr><td>Nuts<td>7</table>'
        '<table><tr><td><table><tr><td>inner A</td><td>inner B</td></tr></table></td><td>outer</td></tr></table>'
        '<blockquote>level one<blockquote>level two<blockquote>level three</blockquote></blockquote></blockquote>'
        '<pre>  indented\n\ttabbed\n    code</pre><p><b>bold <i>both</b> italic</i> after</p><p>unclosed<p>next<li>stray li'),
        contains=["Title\n\nSub\n\nPara one.\n\nPara two\nwith break\n\nafter breaks", "----------", "• apple\n• banana\n  • nested\n    7. seven\n    20. twenty\n    21. twentyone\n• cherry",
                  "1. para in li", "2. second", "Term\nDefinition", "Name | Qty\nBolts | 12\nNuts | 7", "inner A | inner B",
                  "> level one\n\n> > level two\n\n> > > level three", "  indented\n\ttabbed\n    code", "bold both italic after",
                  "unclosed\n\nnext"])

    add("hostile-extras", doc(
        '<img src="http://127.0.0.1:8080/pixel.gif" width="1" height="1" alt="tracking pixel">'
        '<img src="https://track.example/open.gif" alt="">'
        '<p>Visible</p><base href="file:///"><meta http-equiv="refresh" content="0;url=https://x.invalid/">'
        '<a href="https://example.com/ok" onclick="steal()">ok</a><form action="https://x.invalid/"><input value="SECRETVALUE"></form>'),
        contains=["Visible", "ok [1]"], absent=["127.0.0.1", "track.example", "pixel", "x.invalid", "SECRETVALUE", "steal"],
        links=["https://example.com/ok"])

    # Entities and malformed markup.
    add("entities", doc('<p>&amp; &lt;tag&gt; &copy; &hearts; &#128512; &#xD800; &#0; &#x96; &bogus; &amp</p>'),
        contains=["& <tag> © ♥ 😀 \ufffd \ufffd \u2013 &bogus; &"])
    add("malformed", "<p>start<<<>>> <b <i>x</i> <a href='https://example.com/q>unterminated quote</a> "
        "<div><span>open</div></span></table></td></tr> <!-- unterminated comment swallows " + "rest " * 10,
        contains=["start<<<>>>"], absent=["swallows"])
    add("plaintext-script", doc("<p>before</p><script>var x = '</p>visible?';</script><p>after</p><plaintext><b>raw</b> &amp; rest"),
        contains=["before", "after", "<b>raw</b> &amp; rest"], absent=["var x"])
    add("unterminated-script", doc("<p>shown</p><script>never(); <p>swallowed</p>"), contains=["shown"], absent=["swallowed", "never"])
    add("nul-bytes", "<p>a\x00b\x00c</p>", contains=["abc"], stats_min={"removed.control": 2})

    # Bounds.
    words = ("lorem ipsum dolor sit amet " * 40 + "\n")
    huge = "<p>" + (words * (MAX_INPUT // len(words)))[:MAX_INPUT - 200] + "</p>"
    add("huge-text", huge, contains=["[The text of this message was truncated]"], stats={"truncated": True})
    add("huge-line", "<p>" + "x" * (2 << 20) + "</p>", stats_min={"forced_line_breaks": 200}, stats={"truncated": True})
    add("huge-line-cjk", "<p>" + "漢" * 600_000 + "</p>", stats_min={"forced_line_breaks": 80})
    add("deep-div-100k", "<div>" * 100_000 + "BOTTOMTEXT" + "</div>" * 100_000, contains=["BOTTOMTEXT"],
        stats_min={"depth_overflow_elements": 1})
    add("deep-span-unclosed-400k", "<span>" * 400_000 + "DEEPTEXT", contains=["DEEPTEXT"])
    add("deep-hidden-then-overflow", '<div style="display:none">' + "<div>" * 2000 + "HIDDENDEEP" + "</div>" * 2000 + "</div><p>SHOWNAFTER</p>",
        contains=["SHOWNAFTER"], absent=["HIDDENDEEP"])
    add("deep-blockquote-1000", "<blockquote>" * 1000 + "deep quote", contains=["> > > > > > > > deep quote"])
    add("deep-list-1000", "<ul><li>" * 1000 + "deep item", contains=["deep item"])
    add("misnest-many", "<b><i>x</b>y</i>" * 200_000, stats_min={"elements": 400_000})
    add("huge-style-attr", '<p style="color:red;' + "x:y;" * 300_000 + 'display:none">SHOWNBEYONDSCAN</p>', contains=["SHOWNBEYONDSCAN"])
    add("huge-sheet", "<style>" + ".c{color:red} " * 250_000 + "</style><p class=c>after sheet</p>", contains=["after sheet"],
        stats_min={"sheet_rules": 512})
    add("attr-flood", "<p " + " ".join(f'a{i}="{i}"' for i in range(200_000)) + ' style="display:none">SHOWNAFTERCAP</p><p>NEXTPARA</p>',
        contains=["SHOWNAFTERCAP", "NEXTPARA"], stats={"tags_with_attributes_capped": 1})
    add("attr-flood-in-comment", "<!-- <p " + "a " * 100_000 + "> --><p>VISIBLEAFTERCOMMENT</p>", contains=["VISIBLEAFTERCOMMENT"],
        absent=["a a a"], stats={"tags_with_attributes_capped": 0})
    # Regressions found by the fuzz campaign: a non-ASCII character after a selector part; long runs of
    # preformatted whitespace (the forced line break must cover every byte, not only visible characters).
    add("selector-non-ascii", "<style>.pre\u202eheader{display:none} .x\u200b{color:red} #\u202e{display:none}</style><p class=pre>kept</p>",
        contains=["kept"])
    add("pre-whitespace-run", "<pre>" + " " * 10_000 + "x" + "\t" * 9_000 + "y</pre><table><tr>" + "<td>c" * 3000 + "</table>",
        contains=["x", "y"], stats_min={"forced_line_breaks": 4})
    add("many-classes", '<p class="' + " ".join(f"c{i}" for i in range(50_000)) + '">classy</p>', contains=["classy"])
    add("many-anchors", '<a href="https://a.example/">x</a>' * 120_000, stats={"links": 1})
    add("empty", "", exact="")
    add("whitespace-only", "<p>   </p>\n\n<div>\t</div>", exact="")
    add("image-only", doc('<a href="https://shop.example/"><img src="cid:hero" alt="Autumn sale: 30% off"></a><img src="cid:logo" alt="Shop logo">'),
        contains=["[Autumn sale: 30% off] [1]", "[Shop logo]"], links=["https://shop.example/"])
    add("invalid-utf8", b"<p>caf\xe9 na\xefve \xff\xfe ok</p>", contains=["caf\ufffd na\ufffdve \ufffd\ufffd ok"],
        stats={"input_lossy_utf8": True})
    return F


def write_fixtures(outdir):
    os.makedirs(outdir, exist_ok=True)
    tsv, expect = [], {}
    for name, f in fixtures().items():
        raw = f["html"] if isinstance(f["html"], bytes) else f["html"].encode("utf-8", "surrogatepass")
        assert len(raw) <= MAX_INPUT, (name, len(raw))
        p = os.path.join(outdir, f"tf-{name}.html")
        with open(p, "wb") as fh:
            fh.write(raw)
        tsv.append(f"tf-{name}\t{p}")
        expect[f"tf-{name}"] = {k: v for k, v in f.items() if k not in ("html",)} | {"bytes": len(raw)}
    with open(os.path.join(outdir, "fixtures.tsv"), "w") as fh:
        fh.write("\n".join(tsv) + "\n")
    with open(os.path.join(outdir, "expect.json"), "w") as fh:
        json.dump(expect, fh, indent=1, ensure_ascii=True)
    print(f"fixtures: {len(tsv)} documents")


# ---- fuzz -------------------------------------------------------------------------------------

BLOCK = ["p", "div", "h1", "h3", "blockquote", "pre", "ul", "ol", "li", "table", "tr", "td", "th", "dl", "dt", "dd", "center",
         "section", "header", "footer", "hr", "br", "address", "figure", "details", "summary", "tbody", "caption"]
INLINE = ["span", "b", "i", "u", "font", "a", "a", "a", "img", "img", "em", "strong", "small", "sup", "sub", "code", "q", "s",
          "mark", "abbr", "wbr", "label", "button", "o:p", "ruby", "rt", "rp", "bdi", "bdo"]
SPECIAL = ["style", "script", "title", "template", "noscript", "svg", "math", "iframe", "object", "select", "option", "textarea",
           "xmp", "plaintext", "noembed", "noframes", "head", "body", "html", "meta", "base", "input", "video", "canvas", "xml", "frameset"]
HIDE = ["display:none", "display: none !important", "visibility:hidden", "visibility:visible", "mso-hide:all", "opacity:0",
        "opacity:0.01", "font-size:0", "font-size:1px", "font-size:0.5em", "font:0/0 a", "max-height:0", "max-height:0px",
        "height:0", "width:1px", "overflow:hidden", "position:absolute", "left:-9999px", "top:-5000px", "text-indent:-9999px",
        "clip:rect(0 0 0 0)", "clip-path:inset(50%)", "color:#fff", "color:#ffffff", "color:#000", "color:transparent",
        "color:rgba(0,0,0,0)", "color:white", "background:#fff", "background-color:#000", "background:url(x.png)",
        "background:#123 url(y)", "color:rgb(255,255,255)", "display:block", "display:inline-block", "font-size:14px",
        "font-size:large", "color:#feffff", "line-height:0", "max-width:0", "color:" + "#" * 300, "display:", ":", ";;;",
        "/* c */display:none", "display/**/:none", "display:none\\9", "COLOR:#FFF", "Display:NONE", "background:linear-gradient(#fff,#fff)"]
HREFS = ["https://example.com/", "http://example.com/x?y=1&z=2", "mailto:a@example.com", "javascript:alert(1)", "JaVaScRiPt:x",
         "java\tscript:x", " https://spaced.example/ ", "data:text/html,<b>", "vbscript:x", "file:///etc/passwd", "cid:abc",
         "/rel", "#frag", "", "https://\u0430pple.com/", "https://e.example/\u202egnp.exe", "https://user:pw@host.example:8080/p",
         "https://" + "a" * 2100 + ".example/", "http://[::1]/", "https://xn--80ak6aa92e.com/", "https://example.com/%00%0a",
         "https://ex ample.com/", "https://例え.jp/パス", "mailto:", "https:", "http://"]
TEXTS = ["hello world", "Lorem ipsum dolor sit amet, consectetur.", "日本語のテキスト", "中文内容", "한국어", "שלום עולם",
         "مرحبا بالعالم", "می\u200cخواهم", "क्\u200dष", "ภาษาไทย", "👨\u200d👩\u200d👧", "🏴\U000E0067\U000E0062\U000E007F", "1\ufe0f\u20e3",
         "Z\u0336\u0321\u0322\u031b\u0316\u0317\u0318\u0319", "\u202eevil\u202c", "\u2066iso\u2069", "\u200e\u200f\u061c",
         "\u200b\u2060\ufeff\u00ad", "\u200c\u200d\u200c\u200d", "\U000E0041\U000E0042", "\ufe0f\ufe0f\ufe0f", "\u2028\u2029",
         "\x01\x02\x1b[0m\x7f", "\u0085\u009b", "&amp;&lt;&gt;&nbsp;&copy;", "&#x202e;&#8203;&#x1b;&#0;&#xD800;&#x110000;", "&zwnj;&nbsp;" * 20,
         "  \t\n  ", "\ufffd", "\U0010FFFF\uFFFE", "a" * 300, "word " * 50, "<", ">", "&", "\"", "'", "</", "<!--", "-->", "<![CDATA[x]]>",
         "<?pi ?>", "<!DOCTYPE x>", "\x00"]
COLORS = ["#fff", "#ffffff", "white", "#000", "black", "#336699", "red", "transparent", "#fffffe", "rgb(1,2,3)", "zzz", "#12"]


class Fuzz:
    def __init__(self, seed):
        self.r = random.Random(seed)

    def text(self):
        r = self.r
        return "".join(r.choice(TEXTS) for _ in range(r.randrange(1, 5)))

    def style(self):
        r = self.r
        return ";".join(r.choice(HIDE) for _ in range(r.randrange(1, 6)))

    def attrs(self, tag):
        r = self.r
        out = []
        for _ in range(r.choices([0, 1, 2, 4, 30], [3, 4, 3, 1, 0.1])[0]):
            k = r.random()
            if k < 0.35:
                out.append(f'style="{self.style()}"')
            elif k < 0.5:
                out.append(f'class="{r.choice(["preheader", "hide", "mob", "c1 c2", "x"])}"')
            elif k < 0.6:
                out.append(f'href="{r.choice(HREFS)}"')
            elif k < 0.68:
                out.append(f'bgcolor="{r.choice(COLORS)}"')
            elif k < 0.74:
                out.append(f'color="{r.choice(COLORS)}"')
            elif k < 0.8:
                out.append(f'alt="{self.text()}"')
            elif k < 0.85:
                out.append(r.choice(["hidden", "width=1", "height=0", "width=600", "start=-5", "start=99999999999",
                                     "value=3", "dir=rtl", "background=x.jpg", "size=1", "text=#fff"]))
            elif k < 0.9:
                out.append(f'id="{r.choice(["pre", "a", "b"])}"')
            else:
                out.append(f'{r.choice(["data-x", "onclick", "title", "src", "srcset"])}="{self.text()}"')
        return (" " + " ".join(out)) if out else ""

    def element(self, depth, budget):
        r = self.r
        if depth <= 0 or budget[0] <= 0:
            return self.text()
        budget[0] -= 1
        k = r.random()
        tag = r.choice(BLOCK) if k < 0.45 else r.choice(INLINE) if k < 0.9 else r.choice(SPECIAL)
        if tag == "style":
            rules = "".join(f'{r.choice([".preheader", "#pre", "p", ".hide", "div.mob", "a:hover", "td + td", "*", ".c1.c2"])}'
                            f'{{{self.style()}}}' for _ in range(r.randrange(1, 8)))
            if r.random() < 0.3:
                rules = f"@media (max-width:600px){{{rules}}}"
            return f"<style>{rules}</style>" if r.random() < 0.95 else f"<style>{rules}"
        inner = "".join(self.element(depth - 1, budget) if r.random() < 0.55 else self.text() for _ in range(r.randrange(0, 6)))
        close = f"</{tag}>" if r.random() < 0.85 else (f"</{r.choice(BLOCK + INLINE)}>" if r.random() < 0.5 else "")
        sc = "/" if r.random() < 0.05 else ""
        return f"<{tag}{self.attrs(tag)}{sc}>{inner}{close}"

    def document(self):
        r = self.r
        shape = r.choices(["tree", "hidden", "nest", "repeat", "chars", "links", "tables", "mutate", "bytes"],
                          [28, 14, 8, 8, 10, 6, 6, 14, 6])[0]
        k = r.random()
        target = r.randrange(1 << 10, 20 << 10) if k < 0.75 else r.randrange(20 << 10, 200 << 10) if k < 0.95 else \
            r.randrange(200 << 10, 1536 << 10) if k < 0.995 else r.randrange(1536 << 10, MAX_INPUT - 4096)
        if shape in ("tree", "hidden", "mutate", "bytes"):
            parts, size = [], 0
            while size < target:
                e = self.element(r.randrange(1, 10), [r.randrange(3, 120)])
                if shape == "hidden":
                    e = f'<div style="{self.style()}">{e}</div>'
                parts.append(e)
                size += len(e.encode("utf-8", "surrogatepass"))
                if len(parts) > 64 and size < target // 4:   # repeat for speed on big targets
                    parts = parts * max(1, target // max(1, size))
                    break
            body = "".join(parts)
        elif shape == "nest":
            n = min(target // 10, r.choice([300, 3000, 30000, 200000]))
            tag = r.choice(["div", "span", "b", "font", "table", "td", "li", "ul", "blockquote", "a", "p", "pre", "svg", "select"])
            opener = f"<{tag}{self.attrs(tag)}>"
            body = opener * n + self.text() + (f"</{tag}>" * n if r.random() < 0.5 else "")
        elif shape == "repeat":
            unit = self.element(r.randrange(1, 5), [r.randrange(1, 15)])
            body = unit * max(1, target // max(1, len(unit.encode("utf-8", "surrogatepass"))))
        elif shape == "chars":
            body = "<p>" + "".join(r.choice(TEXTS) for _ in range(max(1, target // 12))) + "</p>"
        elif shape == "links":
            body = "".join(f'<a href="{r.choice(HREFS)}{r.randrange(1000) if r.random() < 0.5 else ""}"{self.attrs("a")}>{self.text()}</a> '
                           for _ in range(max(1, target // 60)))
        else:  # tables
            cells = lambda: "".join(f"<td{self.attrs('td')}>{self.text()}" + ("</td>" if r.random() < 0.7 else "") for _ in range(r.randrange(1, 6)))
            body = "<table>" + "".join(f"<tr>{cells()}" for _ in range(max(1, target // 80))) + "</table>"
        head = f"<style>.preheader{{display:none}} .hide{{{self.style()}}}</style>" if r.random() < 0.4 else ""
        text = doc(body, head) if r.random() < 0.85 else body
        raw = text.encode("utf-8", "surrogatepass")
        if shape == "mutate":
            b = bytearray(raw)
            for _ in range(r.randrange(1, 100)):
                if not b:
                    break
                p = r.randrange(len(b))
                op = r.random()
                if op < 0.4:
                    b[p:p] = r.choice([b"<", b">", b"\"", b"'", b"=", b"&", b"</", b"<!--", b"-->", b"\x00", b"<script>", b"<style>",
                                       b"<plaintext>", b"<![CDATA[", b"<svg>", b"</table>", "\u202e".encode()])
                elif op < 0.7:
                    del b[p:p + r.randrange(1, 64)]
                else:
                    q = r.randrange(len(b))
                    b[p:p] = b[q:q + r.randrange(1, 400)]
            raw = bytes(b)
        elif shape == "bytes":
            b = bytearray(raw)
            for _ in range(r.randrange(1, 40)):
                if b:
                    b[r.randrange(len(b))] = r.randrange(256)   # invalid UTF-8 likely: lossy decode path
            raw = bytes(b)
        if len(raw) > MAX_INPUT:
            raw = raw[:MAX_INPUT]
        return shape, raw


def write_fuzz(outdir, count, seed):
    os.makedirs(outdir, exist_ok=True)
    count, seed = int(count), int(seed)
    g = Fuzz(seed)
    manifest, tsv, batch = [], [], 0
    for i in range(count):
        shape, raw = g.document()
        name = f"tz{seed}-{i:05d}-{shape}"
        p = os.path.join(outdir, name + ".html")
        with open(p, "wb") as f:
            f.write(raw)
        manifest.append({"name": name, "shape": shape, "bytes": len(raw)})
        tsv.append(f"{name}\t{p}")
        if len(tsv) == 64 or i == count - 1:
            with open(os.path.join(outdir, f"batch-{batch:03d}.tsv"), "w") as f:
                f.write("\n".join(tsv) + "\n")
            tsv, batch = [], batch + 1
    with open(os.path.join(outdir, "manifest.json"), "w") as f:
        json.dump({"seed": seed, "count": count, "documents": manifest}, f, indent=0)
    sizes = sorted(m["bytes"] for m in manifest)
    print(f"text fuzz: {count} documents, {batch} batches, bytes p50 {sizes[len(sizes) // 2]} max {sizes[-1]} total {sum(sizes)}")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"fixtures": write_fixtures, "fuzz": write_fuzz}[cmd](*args)
