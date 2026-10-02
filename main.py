"""Entry point. Two launch modes, one file.

- `python main.py` (VPS, Docker, local): no server in this process, so start
  one via st.App().
- `streamlit run main.py` (Community Cloud, local streamlit run): the server
  is ALREADY running in this process -- a second .run() raises
  "StreamlitAPIException: A Streamlit server is already running in this
  process" and the app shows a red screen. In that mode the UI from app.py
  is executed inline instead.

Target: Streamlit >= 1.59.0.

This file is a launcher, not the app. The UI lives in app.py, which stays
import-safe so AppTest and unit tests can use it: AppTest.from_file("app.py")
never executes this file, so the server start below cannot collide with a
test runtime.

Do not add sys.argv manipulation or streamlit.web.cli.main -- those are
pre-1.59 workarounds. Do not put UI here: st.App() re-executes app.py,
and anything here would run twice (once bare at import, once per session).
"""

from pathlib import Path

import streamlit as st
from streamlit import runtime

APP_DIR = Path(__file__).resolve().parent


def main() -> None:
    if runtime.exists():
        # Already inside a server (`streamlit run`, incl. Community Cloud):
        # run the UI inline instead of starting a second server.
        # NOTE: runtime.exists() is an internal API and may drift. If it ever
        # disappears, the robust fallback is try/except StreamlitAPIException
        # around st.App(...).run() with the same runpy inline execution.
        import runpy

        runpy.run_path(str(APP_DIR / "app.py"), run_name="__main__")
        return
    # Absolute path: script_path resolution differs by launch mode
    # (streamlit run -> relative to the script; uvicorn -> relative to CWD).
    st.App(str(APP_DIR / "app.py")).run()


if __name__ == "__main__":
    main()
