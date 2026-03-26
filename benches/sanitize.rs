use criterion::{black_box, criterion_group, criterion_main, Criterion};
use htmlsanitizer::sanitize;

fn bench_sanitize(c: &mut Criterion) {
    let html = "<div class=\"container\"><p>Hello <strong>world</strong>!</p>\
        <a href=\"http://example.com\">link</a>\
        <img src=\"http://example.com/img.png\" alt=\"test\" />\
        <script>alert('xss')</script></div>"
        .repeat(100);
    let data = html.as_bytes();

    c.bench_function("sanitize", |b| b.iter(|| sanitize(black_box(data))));
}

criterion_group!(benches, bench_sanitize);
criterion_main!(benches);
