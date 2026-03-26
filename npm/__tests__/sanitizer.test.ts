import { describe, it, expect } from "vitest";
import { sanitize, HtmlSanitizer } from "../src/index.js";

// NOTE: These tests require a wasm-pack build to have been run first:
//   wasm-pack build .. --target bundler --out-dir npm/pkg -- --features wasm
// The bundler target auto-initializes the WASM module on import.

describe("sanitize()", () => {
  it("passes through safe HTML", () => {
    expect(sanitize("<p>Hello</p>")).toBe("<p>Hello</p>");
  });

  it("passes through plain text", () => {
    expect(sanitize("Hello world")).toBe("Hello world");
  });

  it("preserves allowed tags with attributes", () => {
    expect(sanitize('<a href="http://example.com" class="link">text</a>')).toBe(
      '<a href="http://example.com/" class="link">text</a>',
    );
  });

  it("preserves img with safe src", () => {
    expect(sanitize('<img src="http://example.com/img.png" alt="test">')).toBe(
      '<img src="http://example.com/img.png" alt="test">',
    );
  });

  // --- XSS test vectors from OWASP / Go test suite ---

  it("strips script tags", () => {
    expect(
      sanitize('<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT xxx>'),
    ).toBe("");
  });

  it("strips javascript: in href", () => {
    expect(sanitize('<a href="javascript:alert(1)">link</a>')).toBe(
      "<a>link</a>",
    );
  });

  it("strips javascript: in img src", () => {
    expect(sanitize('<IMG SRC="javascript:alert(\'XSS\');">')).toBe("<img>");
  });

  it("strips javascript: case-insensitive", () => {
    expect(sanitize("<IMG SRC=JaVaScRiPt:alert('XSS')>")).toBe("<img>");
  });

  it("strips javascript: with HTML entities", () => {
    expect(
      sanitize('<IMG SRC=javascript:alert(&quot;XSS&quot;)>'),
    ).toBe("<img>");
  });

  it("strips javascript: with backtick", () => {
    expect(
      sanitize('<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>'),
    ).toBe("<img>");
  });

  it("strips onmouseover event handler (quoted)", () => {
    expect(
      sanitize('\\<a onmouseover="alert(document.cookie)"\\>xxs link\\</a\\>'),
    ).toBe("\\<a>xxs link\\</a>");
  });

  it("strips onmouseover event handler (unquoted)", () => {
    expect(
      sanitize("\\<a onmouseover=alert(document.cookie)\\>xxs link\\</a\\>"),
    ).toBe("\\<a>xxs link\\</a>");
  });

  it("strips script after malformed img", () => {
    expect(sanitize('<IMG """><SCRIPT>alert("XSS")</SCRIPT>"\\>')).toBe(
      '<img>"\\&gt;',
    );
  });

  it("strips javascript: with String.fromCharCode", () => {
    expect(
      sanitize("<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>"),
    ).toBe("<img>");
  });

  it("keeps safe src, strips onmouseover", () => {
    expect(sanitize('<IMG SRC=#abc onmouseover="alert(\'xxs\')">')).toBe(
      '<img src="#abc">',
    );
  });

  it("strips onerror event handler", () => {
    expect(sanitize('<IMG onmouseover="alert(\'xxs\')">')).toBe("<img>");
  });

  it("keeps safe src, strips onerror", () => {
    expect(
      sanitize(
        '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
      ),
    ).toBe('<img src="/"></img>');
  });

  it("strips encoded javascript: via HTML entity decimal refs", () => {
    expect(
      sanitize(
        "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
      ),
    ).toBe("<img>");
  });

  it("strips encoded javascript: via hex entity refs", () => {
    expect(
      sanitize(
        "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",
      ),
    ).toBe("<img>");
  });

  it("strips javascript: with embedded tab", () => {
    expect(sanitize("<IMG SRC=\"jav\tascript:alert('XSS');\">")).toBe("<img>");
  });

  it("strips ftp: protocol in href", () => {
    expect(sanitize('<a href="ftp://example.com/xxx">test</a xxx>')).toBe(
      "<a>test</a>",
    );
  });

  it("strips script tag with attributes", () => {
    expect(
      sanitize(
        '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>',
      ),
    ).toBe("");
  });

  it("strips nested script in script", () => {
    expect(sanitize('<<SCRIPT>alert("XSS");//\\<</SCRIPT>')).toBe(
      'alert("XSS");//\\',
    );
  });

  it("strips svg/onload", () => {
    expect(sanitize("<svg/onload=alert('XSS')>")).toBe("");
  });

  it("strips iframe with javascript:", () => {
    expect(sanitize('<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>')).toBe(
      "",
    );
  });

  it("strips OBJECT tag", () => {
    expect(
      sanitize(
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>',
      ),
    ).toBe("");
  });

  it("strips EMBED tag", () => {
    expect(sanitize('<EMBED SRC="data:image/svg+xml;base64,abc">')).toBe("");
  });

  it("strips LINK tag", () => {
    expect(
      sanitize('<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">'),
    ).toBe("");
  });

  it("strips BASE tag", () => {
    expect(sanitize('<BASE HREF="javascript:alert(\'XSS\');//">')).toBe("");
  });

  it("handles attribute edge cases", () => {
    expect(sanitize('<a class="\'<>" rel=\'aaa"\'> test</a>')).toBe(
      '<a class="&#39;&lt;&gt;" rel="aaa&#34;"> test</a>',
    );
  });

  it("handles audio with boolean attributes", () => {
    expect(sanitize("<audio autoplay class=x>")).toBe(
      '<audio autoplay class="x">',
    );
  });

  it("handles self-closing audio", () => {
    expect(sanitize("<audio autoplay />")).toBe("<audio autoplay />");
  });

  it("handles empty attribute value", () => {
    expect(sanitize("<span class=>")).toBe('<span class="">');
  });

  it("handles unclosed tags", () => {
    expect(sanitize("<span")).toBe("");
    expect(sanitize("</span")).toBe("");
    expect(sanitize("<span class")).toBe("");
  });

  it("keeps IP address URLs", () => {
    expect(sanitize('<A HREF="http://66.102.7.147/">XSS</A>')).toBe(
      '<a href="http://66.102.7.147/">XSS</a>',
    );
  });

  it("rejects percent-encoded host", () => {
    expect(
      sanitize(
        '<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>',
      ),
    ).toBe("<a>XSS</a>");
  });

  it("strips STYLE tag content", () => {
    expect(
      sanitize(
        "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS</br>",
      ),
    ).toBe("<ul><li>XSS</br>");
  });

  it("handles complex multi-vector XSS input", () => {
    const input = `
<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">
<Video> <source onerror = "javascript: alert (XSS)">
<Input value = "XSS" type = text>
<applet code="javascript:confirm(document.cookie);">
<isindex x="javascript:" onmouseover="alert(XSS)">
"></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
"><img src="x:x" onerror="alert(XSS)">
"><iframe src="javascript:alert(XSS)">
<object data="javascript:alert(XSS)" />
<isindex type=image src=1 onerror=alert(XSS)>
<img src=x:alert(alt) onerror=eval(src) alt=0>
<img  src="x:gif" onerror="window['al\\u0065rt'](0)"></img>
<iframe/src="data:text/html,<svg onload=alert(1)>">
<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>
<svg><script xlink:href=data&colon;,window.open('https://www.google.com/')></script
<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">
<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>
<form><a href="javascript:\\u0061lert(1)">X
</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror='eval(src)'>
<style>//*{x:expression(alert(/xss/))}//<style></style>
On Mouse Over\u200B
<img src="/" =_=" title="onerror='prompt(1)'">
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script:&#97lert(1)>ClickMe
<script x> alert(1) </script 1=2
<form><button formaction=javascript&colon;alert(1)>CLICKME
<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"
<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E"></iframe>
<OBJECT CLASSID="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83"><PARAM NAME="DataURL" VALUE="javascript:alert(1)"></OBJECT>
`;

    const result = sanitize(input);

    // Verify no script content leaks through
    expect(result).not.toContain("<script");
    expect(result).not.toContain("<SCRIPT");
    expect(result).not.toContain("alert(");
    expect(result).not.toContain("onerror");
    expect(result).not.toContain("onmouseover");
    expect(result).not.toContain("onload");
    expect(result).not.toContain("javascript:");
    expect(result).not.toContain("onclick");

    // Safe content should remain
    expect(result).toContain("<img");
    expect(result).toContain("<video>");
    expect(result).toContain("ClickMe");
    expect(result).toContain("CLICKME");
    expect(result).toContain("On Mouse Over");
  });
});

describe("HtmlSanitizer class", () => {
  it("constructs successfully", () => {
    const s = new HtmlSanitizer();
    expect(s).toBeInstanceOf(HtmlSanitizer);
    s.free();
  });

  it("sanitizes with default allow list", () => {
    const s = new HtmlSanitizer();
    expect(s.sanitize("<p>hello</p>")).toBe("<p>hello</p>");
    expect(s.sanitize('<script>alert("xss")</script>')).toBe("");
    s.free();
  });

  it("removeTag removes a tag", () => {
    const s = new HtmlSanitizer();
    s.removeTag("a");
    expect(s.sanitize('<a href="http://example.com">link</a>')).toBe("link");
    // Other tags still work
    expect(s.sanitize("<p>text</p>")).toBe("<p>text</p>");
    s.free();
  });

  it("removeTag for img", () => {
    const s = new HtmlSanitizer();
    s.removeTag("img");
    expect(s.sanitize('<img src="http://example.com/i.png">')).toBe("");
    s.free();
  });

  it("addTag adds a custom tag", () => {
    const s = new HtmlSanitizer();
    // "custom" is not in default allow list
    expect(s.sanitize("<custom>content</custom>")).toBe("content");
    s.addTag("custom", "", "");
    expect(s.sanitize("<custom>content</custom>")).toBe(
      "<custom>content</custom>",
    );
    s.free();
  });

  it("addTag with attributes", () => {
    const s = new HtmlSanitizer();
    s.addTag("custom", "data-x,title", "href");
    const html =
      '<custom data-x="1" title="t" href="http://example.com" onclick="bad">content</custom>';
    const result = s.sanitize(html);
    expect(result).toContain('data-x="1"');
    expect(result).toContain('title="t"');
    expect(result).toContain('href="http://example.com/"');
    expect(result).not.toContain("onclick");
    s.free();
  });

  it("addGlobalAttr allows attribute on all tags", () => {
    const s = new HtmlSanitizer();
    s.addGlobalAttr("data-testid");
    expect(s.sanitize('<p data-testid="main">text</p>')).toBe(
      '<p data-testid="main">text</p>',
    );
    expect(s.sanitize('<span data-testid="x">text</span>')).toBe(
      '<span data-testid="x">text</span>',
    );
    s.free();
  });

  it("multiple instances are independent", () => {
    const s1 = new HtmlSanitizer();
    const s2 = new HtmlSanitizer();

    s1.removeTag("a");

    // s1 should strip <a>, s2 should keep it
    expect(s1.sanitize('<a href="http://example.com">link</a>')).toBe("link");
    expect(s2.sanitize('<a href="http://example.com">link</a>')).toBe(
      '<a href="http://example.com/">link</a>',
    );

    s1.free();
    s2.free();
  });
});

describe("TypeScript types", () => {
  it("sanitize accepts string and returns string", () => {
    const result: string = sanitize("<p>test</p>");
    expect(typeof result).toBe("string");
  });

  it("HtmlSanitizer methods have correct signatures", () => {
    const s = new HtmlSanitizer();
    expect(typeof s.sanitize).toBe("function");
    expect(typeof s.removeTag).toBe("function");
    expect(typeof s.addTag).toBe("function");
    expect(typeof s.addGlobalAttr).toBe("function");
    expect(typeof s.free).toBe("function");
    s.free();
  });
});
