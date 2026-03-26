#[cfg(test)]
mod tests {
    use htmlsanitizer::sanitize_string;

    #[test]
    fn go_test_cases() {
        let cases: Vec<(&str, &str)> = vec![
            (
                "<a class=\"'<>\" rel='aaa\"'>test</a>",
                "<a class=\"&#39;&lt;&gt;\" rel=\"aaa&#34;\">test</a>",
            ),
            (
                "<a href=\"ftp://example.com/xxx\">test</a xxx>",
                "<a>test</a>",
            ),
            ("<audio autoplay class=x>", "<audio autoplay class=\"x\">"),
            ("<audio autoplay />", "<audio autoplay />"),
            (
                "<audio autoplay/class=\"a\">",
                "<audio autoplay class=\"a\">",
            ),
            ("<span class=>", "<span class=\"\">"),
            ("<span", ""),
            ("</span", ""),
            ("<span class", ""),
            ("</span class", ""),
            ("<span class  ", ""),
            ("<span class=  ", ""),
            ("<span class=\"  ", ""),
            ("<span class=  >", "<span class=\"\">"),
            ("<span class=  />", "<span class=\"/\">"),
            ("<span class  =   abc", ""),
            ("<span class  =   a>", "<span class=\"a\">"),
            ("<//>", ""),
            ("<//", ""),
            // OWASP XSS test cases
            (
                "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT xxx>",
                "",
            ),
            (
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "javascript:/*--&gt;",
            ),
            ("<IMG SRC=\"javascript:alert('XSS');\">", "<img>"),
            ("<IMG SRC=javascript:alert('XSS')>", "<img>"),
            ("<IMG SRC=JaVaScRiPt:alert('XSS')>", "<img>"),
            (
                "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
                "<img>",
            ),
            (
                "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
                "<img>",
            ),
            (
                "\\<a onmouseover=\"alert(document.cookie)\"\\>xxs link\\</a\\>",
                "\\<a>xxs link\\</a>",
            ),
            (
                "\\<a onmouseover=alert(document.cookie)\\>xxs link\\</a\\>",
                "\\<a>xxs link\\</a>",
            ),
            (
                "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\"\\>",
                "<img>\"\\&gt;",
            ),
            (
                "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
                "<img>",
            ),
            (
                "<IMG SRC=#abc onmouseover=\"alert('xxs')\">",
                "<img src=\"#abc\">",
            ),
            (
                "<IMG SRC= onmouseover=\"alert('xxs')\">",
                "<img src=\"onmouseover=%22alert%28%27xxs%27%29%22\">",
            ),
            ("<IMG onmouseover=\"alert('xxs')\">", "<img>"),
            (
                "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
                "<img src=\"/\"></img>",
            ),
            (
                "<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">",
                "<img src=\"x\">",
            ),
            (
                "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
                "<img>",
            ),
            (
                "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
                "<img>",
            ),
            (
                "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",
                "<img>",
            ),
            (
                "<IMG SRC=\"jav\tascript:alert('XSS');\">",
                "<img>",
            ),
            (
                "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
                "<img>",
            ),
            (
                "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
                "<img>",
            ),
            (
                "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
                "<img>",
            ),
            (
                "<IMG SRC=java\x00script:alert(\"XSS\")>",
                "<img>",
            ),
            (
                "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
                "<img>",
            ),
            (
                "<SCRIPT/XSS SRC=\"http://xss.rocks/xss.js\"></SCRIPT>",
                "",
            ),
            (
                "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
                "",
            ),
            (
                "<SCRIPT/SRC=\"http://xss.rocks/xss.js\"></SCRIPT>",
                "",
            ),
            (
                "<<SCRIPT>alert(\"XSS\");//\\<</SCRIPT>",
                "alert(\"XSS\");//\\",
            ),
            ("<SCRIPT SRC=http://xss.rocks/xss.js?< B >", ""),
            (
                "<IMG SRC=\"`<javascript:alert>`('XSS')\">",
                "<img>",
            ),
            (
                "<iframe src=http://xss.rocks/scriptlet.html <",
                "",
            ),
            (
                "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
                "",
            ),
            ("<IMG DYNSRC=\"javascript:alert('XSS')\">", "<img>"),
            ("<IMG LOWSRC=\"javascript:alert('XSS')\">", "<img>"),
            (
                "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS</br>",
                "<ul><li>XSS</br>",
            ),
            (
                "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}",
                "",
            ),
            ("<svg/onload=alert('XSS')>", ""),
            (
                "<BR SIZE=\"&{alert('XSS')}\">",
                "<br>",
            ),
            (
                "<LINK REL=\"stylesheet\" HREF=\"http://xss.rocks/xss.css\">",
                "",
            ),
            (
                "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">",
                "<img>",
            ),
            ("<XSS STYLE=\"xss:expression(alert('XSS'))\">", ""),
            (
                "\u{00bc}script\u{00be}alert(\u{00a2}XSS\u{00a2})\u{00bc}/script\u{00be}",
                "\u{00bc}script\u{00be}alert(\u{00a2}XSS\u{00a2})\u{00bc}/script\u{00be}",
            ),
            (
                "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
                "",
            ),
            (
                "<IFRAME SRC=# onmouseover=\"alert(document.cookie)\"></IFRAME>",
                "",
            ),
            (
                "<!--[if gte IE 4]>\n<SCRIPT>alert('XSS');</SCRIPT>\n\t\t<![endif]-->",
                "\n\n\t\t",
            ),
            (
                "<BASE HREF=\"javascript:alert('XSS');//\">",
                "",
            ),
            (
                "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://xss.rocks/scriptlet.html\"></OBJECT>",
                "",
            ),
            (
                "<EMBED SRC=\"data:image/svg+xml;base64,xxx\" type=\"image/svg+xml\" AllowScriptAccess=\"always\"></EMBED>",
                "",
            ),
            (
                "<SCRIPT a=\">\" SRC=\"httx://xss.rocks/xss.js\"></SCRIPT>",
                "",
            ),
            (
                "<SCRIPT =\">\" SRC=\"httx://xss.rocks/xss.js\"></SCRIPT>",
                "",
            ),
            (
                "<A HREF=\"http://66.102.7.147/\">XSS</A>",
                "<a href=\"http://66.102.7.147/\">XSS</a>",
            ),
            (
                "<A HREF=\"http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D\">XSS</A>",
                "<a>XSS</a>",
            ),
            (
                "<A HREF=\"h\n\t\tt  p://6\t6.000146.0x7.147/\">XSS</A>",
                "<a>XSS</a>",
            ),
            (
                "<A HREF=\"javascript:document.location='http://www.google.com/'\">XSS</A>",
                "<a>XSS</a>",
            ),
            (
                "<span>func <a class= \"Documentation-source\" href=\"https://cs.opensource.google/go/go/+/go1.21.5:src/os/path.go;l=66\">RemoveAll</a> <a class=\"Documentation-idLink\" href=\"#RemoveAll\" aria-label=\"Go to RemoveAll\">\u{00b6}</a></span>",
                "<span>func <a class=\"Documentation-source\" href=\"https://cs.opensource.google/go/go/+/go1.21.5:src/os/path.go;l=66\">RemoveAll</a> <a class=\"Documentation-idLink\" href=\"#RemoveAll\">\u{00b6}</a></span>",
            ),
        ];

        for (i, (input, expected)) in cases.iter().enumerate() {
            let got = sanitize_string(input);
            assert_eq!(got, *expected, "case {}: input={:?}", i, input);
        }
    }

    #[test]
    fn test_sanitize_bytes() {
        let data = b"<a class=x id= 123 href=\"javascript:alert(1)\">demo</a>";
        let expected = b"<a class=\"x\" id=\"123\">demo</a>";
        let got = htmlsanitizer::sanitize(data);
        assert_eq!(got, expected);
    }

    #[test]
    fn test_chunked_write() {
        use std::io::Write;

        let inputs = vec![
            "<a href=\"http://example.com\" class=\"link\">text</a>",
            "<script>alert(1)</script><p>safe</p>",
            "<div class=\"c\"><img src=\"http://x.com/i.png\" alt=\"pic\" /></div>",
            "<span style=\"color:red\">hello</span>",
            "<a href='http://example.com'>link</a>",
        ];

        for input in &inputs {
            let expected = sanitize_string(input);
            let data = input.as_bytes();

            for split in 1..data.len() {
                let mut buf = Vec::new();
                {
                    let sanitizer = htmlsanitizer::HtmlSanitizer::new();
                    let mut w = sanitizer.new_writer(&mut buf);
                    w.write_all(&data[..split]).unwrap();
                    w.write_all(&data[split..]).unwrap();
                }
                let got = String::from_utf8(buf).unwrap();
                assert_eq!(
                    got, expected,
                    "chunked write split={} input={:?}",
                    split, input
                );
            }
        }
    }
}
