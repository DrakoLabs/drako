"""CRITICAL: every generated document must contain the verbatim disclaimer."""

from pathlib import Path

import pytest

from drako.comply import LEGAL_DISCLAIMER


def test_disclaimer_constant_is_nonempty() -> None:
    assert LEGAL_DISCLAIMER.startswith("LEGAL DISCLAIMER:")
    assert "MUST be reviewed" in LEGAL_DISCLAIMER
    assert "Drako does not provide legal advice" in LEGAL_DISCLAIMER


def test_disclaimer_in_html_template() -> None:
    base = Path(__file__).resolve().parents[2] / "src/drako/comply/templates/_base.html.j2"
    content = base.read_text(encoding="utf-8")
    assert "{{ legal_disclaimer }}" in content


@pytest.mark.comply
def test_disclaimer_appears_in_pdf_html() -> None:
    pytest.importorskip("jinja2")
    pytest.importorskip("weasyprint")
    from drako.comply.generators.pdf_generator import render_html

    # Build a minimal context inline to avoid fixture dependency here.
    from drako.comply.mapping import ComplianceContext

    from .conftest import sample_ctx  # type: ignore  # noqa: F401

    ctx = ComplianceContext(system_name="X", system_version="1")
    for article in (9, 11, 12, 14):
        html = render_html(article, ctx)
        assert LEGAL_DISCLAIMER in html, f"disclaimer missing in article {article}"


@pytest.mark.comply
def test_disclaimer_appears_in_docx(tmp_path: Path, sample_ctx) -> None:
    docx = pytest.importorskip("docx")
    from drako.comply.generators import generate_docx

    for article in (9, 11, 12, 14):
        out = generate_docx(article, sample_ctx, tmp_path)
        document = docx.Document(str(out))
        text = "\n".join(p.text for p in document.paragraphs)
        assert LEGAL_DISCLAIMER in text, f"disclaimer missing in DOCX article {article}"
