"""AppTest wiring + pure-logic tests. No network, no credentials."""

from datetime import datetime, timezone

import pandas as pd
from streamlit.testing.v1 import AppTest

from soc_data import SEVERITIES, filter_alerts, generate_alerts

FIXED_NOW = datetime(2026, 10, 2, 7, 30, tzinfo=timezone.utc)


def _app():
    at = AppTest.from_file("../app.py", default_timeout=60)
    at.run()
    return at


def test_app_starts_clean():
    at = _app()
    assert not at.exception


def test_kpi_row_renders_four():
    at = _app()
    assert not at.exception
    assert len(at.metric) == 4


def test_filter_flow_and_submit():
    at = _app()
    assert not at.exception
    at.selectbox[0].set_value("EU").run()
    assert not at.exception
    submit = [b for b in at.button if b.label == "Применить"]
    assert submit, "form submit button missing"
    submit[0].click().run()
    assert not at.exception
    assert at.dataframe
    assert at.dataframe[0].value is not None


def test_search_filter_flow():
    at = _app()
    assert not at.exception
    at.text_input[0].set_value("T1110").run()
    assert not at.exception


def test_detail_expander_present():
    at = _app()
    assert not at.exception
    assert at.expander, "incident detail expander missing"


def test_generator_deterministic():
    a = generate_alerts(200, 7, 48, now=FIXED_NOW)
    b = generate_alerts(200, 7, 48, now=FIXED_NOW)
    pd.testing.assert_frame_equal(a, b)


def test_generator_seed_changes_output():
    a = generate_alerts(200, 7, 48, now=FIXED_NOW)
    b = generate_alerts(200, 200, 48, now=FIXED_NOW)
    assert not a.equals(b)


def test_filter_regions_and_severity_floor():
    df = generate_alerts(400, 11, 48, now=FIXED_NOW)
    eu = filter_alerts(df, region="EU", now=FIXED_NOW)
    assert set(eu["region"].unique()) <= {"EU"}
    crit = filter_alerts(df, sev_floor="Critical", now=FIXED_NOW)
    assert set(crit["severity"].unique()) <= {"Critical"}
    assert set(df["severity"].unique()) <= set(SEVERITIES)
