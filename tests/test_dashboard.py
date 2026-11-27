"""Every dashboard page renders from the saved results without errors (skipped if streamlit is not installed)."""
import pathlib

import pytest

pytest.importorskip("streamlit")
pytest.importorskip("plotly")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(pathlib.Path(__file__).resolve().parent.parent / "app" / "dashboard.py")


@pytest.mark.parametrize("page", ["Overview", "Results", "Attack Lab", "Trace Viewer", "Findings"])
def test_page_renders(page):
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception


def test_attack_lab_replays_blocked_call():
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    at.sidebar.radio[0].set_value("Attack Lab").run()   # opens on A3-10
    at.selectbox[2].set_value("full").run()
    assert not at.exception
    assert any("blocked" in e.value for e in at.error)


def test_every_logged_run_has_a_trace():
    import sys
    import zipfile
    sys.path.insert(0, str(pathlib.Path(APP).parent))
    import data as D
    runs = D.runs()
    assert len(runs) == 2727
    for z, g in runs.groupby("zip"):
        names = set(zipfile.ZipFile(z).namelist())
        assert all(f"{m}/trace.json" in names for m in g.member)
