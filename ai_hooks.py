"""Place to plug AI in later.

`analyze_report` is called once, right after a citizen submits a report.
Whatever dict it returns is stored in the report's `ai_analysis` field and
shown to police on the report page. Right now it does nothing.

Ideas to add later:
  * number-plate recognition (ANPR) on the uploaded image/video frames
  * smoke / black-exhaust detection
  * rash-driving or road-rage classification on video
  * duplicate-report detection (same plate + same area + same time)
  * text classification / priority scoring of the description
"""
from __future__ import annotations

from typing import Optional


def analyze_report(report: dict, media_paths: list) -> Optional[dict]:
    # Example of what you might return later:
    # return {"plate": "AP39TX1234", "plate_confidence": 0.91,
    #         "violation_guess": "excessive_smoke", "priority": "high"}
    return None
