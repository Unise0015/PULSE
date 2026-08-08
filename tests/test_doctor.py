import json
from pulse.core.doctor import DoctorRunner, CheckStatus, ConfigurationCheck, FilesystemCheck

def test_doctor_runner_execution():
    score_pct, overall_status, results, cat_scores = DoctorRunner.run_all()

    assert isinstance(score_pct, int)
    assert 0 <= score_pct <= 100
    assert overall_status in (CheckStatus.PASS, CheckStatus.WARNING, CheckStatus.FAIL)
    assert len(results) >= 5
    assert "Configuration" in cat_scores
    assert "Filesystem" in cat_scores


def test_doctor_export_json_and_markdown():
    json_out = DoctorRunner.export(format="json")
    data = json.loads(json_out)

    assert "system_health_score" in data
    assert "overall_status" in data
    assert "category_breakdown" in data
    assert "check_results" in data

    md_out = DoctorRunner.export(format="markdown")
    assert "# PULSE Doctor Diagnostic Report" in md_out
    assert "Score Breakdown" in md_out
