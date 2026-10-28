"""Pure regression tests for WebFig response-body path confinement."""

from app.web.console_proxy import WebFigRootRewriter, should_rewrite_webfig_body


def test_webfig_root_redirect_is_rewritten_inside_console_prefix() -> None:
    prefix = "/labs/instances/12345678-1234-1234-1234-123456789abc/console/r1"
    body = b'window.location = "/webfig/";'
    rewriter = WebFigRootRewriter(prefix)

    assert rewriter.feed(body) + rewriter.finish() == (
        b'window.location = "'
        + prefix.encode()
        + b'/webfig/";'
    )


def test_webfig_root_rewrite_survives_every_chunk_boundary() -> None:
    prefix = "/labs/instances/12345678-1234-1234-1234-123456789abc/console/r1"
    body = b'before:/webfig/:after'
    expected = b"before:" + prefix.encode() + b"/webfig/:after"

    for split in range(len(body) + 1):
        rewriter = WebFigRootRewriter(prefix)
        actual = rewriter.feed(body[:split]) + rewriter.feed(body[split:]) + rewriter.finish()
        assert actual == expected


def test_only_text_and_javascript_responses_are_rewritten() -> None:
    assert should_rewrite_webfig_body("text/html; charset=utf-8")
    assert should_rewrite_webfig_body("text/javascript")
    assert should_rewrite_webfig_body("application/javascript")
    assert not should_rewrite_webfig_body("application/octet-stream")
    assert not should_rewrite_webfig_body(None)
