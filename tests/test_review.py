from __future__ import annotations

import os
import tempfile

from bundlebleed.review import ScanPhaseReview


def _make_output_dir() -> str:
    d = tempfile.mkdtemp()
    # Build minimum expected structure
    for sub in ["raw/external", "raw/inline", "beautified/external", "findings"]:
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    # Drop a placeholder JS file
    with open(os.path.join(d, "raw", "external", "app.js"), "w") as fh:
        fh.write("const x = 1;")
    with open(os.path.join(d, "beautified", "external", "app.js"), "w") as fh:
        fh.write("const x = 1;")
    with open(os.path.join(d, "findings", "scan-result.json"), "w") as fh:
        fh.write("{}")
    with open(os.path.join(d, "findings", "scan-result.md"), "w") as fh:
        fh.write("# report")
    with open(os.path.join(d, "findings", "curls.sh"), "w") as fh:
        fh.write("#!/bin/bash\n")
    with open(os.path.join(d, "findings", "secrets.md"), "w") as fh:
        fh.write("# Secrets\n\n## 5.1 Known-regex matches\n\n_0 known matches._\n")
    return d


def test_phase1_pass() -> None:
    d = _make_output_dir()
    review = ScanPhaseReview(d)
    result = review.check_phase1()
    assert result.coverage_score > 0


def test_phase2_pass() -> None:
    d = _make_output_dir()
    review = ScanPhaseReview(d)
    result = review.check_phase2()
    assert result.passed()


def test_phase2_fails_on_plaintext_secret() -> None:
    d = _make_output_dir()
    with open(os.path.join(d, "findings", "secrets.md"), "w") as fh:
        fh.write("# Secrets\nAKIAIOSFODNN7EXAMPLE\n")
    review = ScanPhaseReview(d)
    result = review.check_phase2()
    assert not result.passed()


def test_write_creates_review_md() -> None:
    d = _make_output_dir()
    review = ScanPhaseReview(d)
    p1 = review.check_phase1()
    p2 = review.check_phase2()
    path = review.write(p1, p2)
    assert os.path.isfile(path)
    content = open(path).read()
    assert "- [" in content


def test_review_md_uses_checkboxes() -> None:
    d = _make_output_dir()
    review = ScanPhaseReview(d)
    p1 = review.check_phase1()
    p2 = review.check_phase2()
    review.write(p1, p2)
    content = open(os.path.join(d, "findings", "review.md")).read()
    assert "- [X]" in content or "- [ ]" in content


def test_missing_scan_result_fails_phase2() -> None:
    d = _make_output_dir()
    os.remove(os.path.join(d, "findings", "scan-result.json"))
    review = ScanPhaseReview(d)
    result = review.check_phase2()
    failed_items = [i for i in result.items if i.status == "FAILED"]
    assert any("scan-result.json" in i.name for i in failed_items)
