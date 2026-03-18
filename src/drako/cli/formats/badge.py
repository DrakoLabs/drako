"""SVG badge generation for Drako governance score.

Produces a shields.io-style badge for embedding in README.md:
  "Drako | Score: 85/100 [B]"
"""

from __future__ import annotations

_GRADE_COLORS = {
    "A": "#4c1",       # bright green
    "B": "#97ca00",    # green
    "C": "#dfb317",    # yellow
    "D": "#fe7d37",    # orange
    "F": "#e05d44",    # red
}

_SVG_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{value_x}" y="14">{value}</text>
  </g>
</svg>"""


def generate_badge_svg(score: int, grade: str) -> str:
    """Generate an SVG badge showing the governance score and grade.

    Returns SVG markup as a string.
    """
    label = "Drako"
    value = f"{score}/100 [{grade}]"
    color = _GRADE_COLORS.get(grade, "#9f9f9f")

    # Approximate text widths (6.5px per char)
    label_width = int(len(label) * 6.5) + 12
    value_width = int(len(value) * 6.5) + 12
    total_width = label_width + value_width
    label_x = label_width / 2
    value_x = label_width + value_width / 2

    return _SVG_TEMPLATE.format(
        total_width=total_width,
        label_width=label_width,
        value_width=value_width,
        color=color,
        label=label,
        value=value,
        label_x=label_x,
        value_x=value_x,
    )
