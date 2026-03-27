import { bench, describe } from "vitest";
import {
  sanitize as wasmSanitize,
  HtmlSanitizer,
} from "../npm/src/index.js";
import createDOMPurify from "dompurify";
import { JSDOM } from "jsdom";

// ── DOMPurify setup ──────────────────────────────────────────────────
const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window as unknown as Window);

// ── Test payloads ────────────────────────────────────────────────────

const payloads: Record<string, string> = {
  // 1. Tiny: plain text, no HTML
  "plain text (tiny)": "Hello, world!",

  // 2. Small: simple safe markup
  "simple HTML (small)":
    '<p>Hello <b>world</b></p><br><a href="https://example.com">link</a>',

  // 3. XSS vectors
  "XSS vectors": [
    '<script>alert("xss")</script>',
    '<img src=x onerror="alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<div onmouseover="alert(1)">hover</div>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<svg onload="alert(1)">',
    '<math><mi xlink:href="javascript:alert(1)">test</mi></math>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">entity</a>',
  ].join("\n"),

  // 4. Medium: realistic blog post
  "blog post (medium)": `
    <article>
      <header><h1>My Blog Post</h1></header>
      <p>This is a <strong>great</strong> article about <em>HTML sanitization</em>.</p>
      <p>Here is a <a href="https://example.com" target="_blank" rel="noopener">link</a>.</p>
      <blockquote cite="https://example.com/quote">
        <p>Someone once said something wise.</p>
      </blockquote>
      <h2>Code Example</h2>
      <pre><code>const x = 1 &lt; 2 &amp;&amp; 3 &gt; 0;</code></pre>
      <ul>
        <li>Item one</li>
        <li>Item two with <code>inline code</code></li>
        <li>Item three</li>
      </ul>
      <figure>
        <img src="https://example.com/photo.jpg" alt="A photo" width="800" height="600" loading="lazy">
        <figcaption>A beautiful photo</figcaption>
      </figure>
      <table>
        <thead><tr><th>Name</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Alpha</td><td>1</td></tr>
          <tr><td>Beta</td><td>2</td></tr>
          <tr><td>Gamma</td><td>3</td></tr>
        </tbody>
      </table>
      <details>
        <summary>Click to expand</summary>
        <p>Hidden content here.</p>
      </details>
      <footer><small>Published <time datetime="2025-01-15">Jan 15</time></small></footer>
    </article>
  `,

  // 5. Mixed: safe + dangerous content interleaved
  "mixed safe+dangerous": `
    <div class="content">
      <h1>Welcome</h1>
      <script>document.cookie</script>
      <p>Normal paragraph with <b>bold</b> text.</p>
      <style>.evil { display: none }</style>
      <img src="https://example.com/img.png" alt="safe" onerror="alert(1)">
      <a href="https://example.com" onclick="steal()">Safe link</a>
      <ul>
        <li>Item <object data="evil.swf">plugin</object></li>
        <li>Normal item</li>
      </ul>
      <iframe src="https://evil.com"></iframe>
      <video src="https://example.com/video.mp4" controls onplay="track()"></video>
    </div>
  `,
};

// 6. Large: repeat the blog post to create a ~50KB payload
payloads["large document (~50KB)"] = payloads["blog post (medium)"].repeat(50);

// ── Benchmarks ───────────────────────────────────────────────────────

for (const [name, html] of Object.entries(payloads)) {
  describe(name, () => {
    bench("@bytevet/htmlsanitizer (WASM)", () => {
      wasmSanitize(html);
    });

    bench("DOMPurify + jsdom", () => {
      DOMPurify.sanitize(html);
    });
  });
}

// ── Instance reuse benchmark ─────────────────────────────────────────

describe("instance reuse (100 calls, medium payload)", () => {
  const mediumHtml = payloads["blog post (medium)"];

  bench("@bytevet/htmlsanitizer (WASM)", () => {
    const s = new HtmlSanitizer();
    for (let i = 0; i < 100; i++) {
      s.sanitize(mediumHtml);
    }
    s.free();
  });

  bench("DOMPurify + jsdom", () => {
    for (let i = 0; i < 100; i++) {
      DOMPurify.sanitize(mediumHtml);
    }
  });
});
