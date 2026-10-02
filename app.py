"""SOC Console. Import-safe UI: no st.* calls at module scope.

Launch via main.py (st.App) or `streamlit run app.py`. Tests use
AppTest.from_file("app.py"), so no server start lives in this file.

Order inside main(): set_page_config -> CSS -> sidebar form -> data ->
KPI row -> hero 2:1 -> live fragment -> table -> expander detail.

Data is 100 percent local synthesis (soc_data, seeded PRNG): no network,
no external calls, no credentials of any kind.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from soc_data import (
    SEED_DEFAULT,
    SEV_ICON,
    VECTORS,
    apply_closed,
    breakdown,
    compute_kpis,
    filter_alerts,
    generate_alerts,
    trend_by_hour,
)

CSS = """
<style>
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1400px; }
    [data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; font-family: "JetBrains Mono", monospace; }
    [data-testid="stDataFrame"] td { font-variant-numeric: tabular-nums; }
    [data-testid="stSidebar"] { border-right: 1px solid rgba(128, 128, 128, 0.18); }
</style>
"""

WINDOW_H = {"6ч": 6, "24ч": 24, "48ч": 48}


# --------------------------------------------------------------------------
# Config access: environment first, st.secrets as the hosted fallback.
# No credentials are required: the fallback only names the sample mode.
# --------------------------------------------------------------------------
def _secret(key: str):
    try:
        return st.secrets[key]
    except (KeyError, FileNotFoundError):
        return None


def console_mode() -> str:
    return os.environ.get("SOC_MODE") or _secret("soc_mode") or "sample"


# --------------------------------------------------------------------------
# Data layer. Cached and bounded. No st.* calls in here.
# --------------------------------------------------------------------------
@st.cache_data(ttl=60, max_entries=8, show_spinner="Обновление потока…")
def load_alerts(n: int, seed: int, hours: int) -> pd.DataFrame:
    return generate_alerts(n=n, seed=seed, hours=hours)


@st.cache_data(ttl=120, max_entries=8)
def cached_kpis(df: pd.DataFrame) -> dict:
    return compute_kpis(df)


@st.cache_data(ttl=120, max_entries=8)
def cached_trend(df: pd.DataFrame, hours: int) -> pd.DataFrame:
    return trend_by_hour(df, hours=hours)


@st.cache_data(ttl=120, max_entries=8)
def cached_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    return breakdown(df)


def _bump_stream() -> None:
    st.session_state["stream_tick"] = st.session_state.get("stream_tick", 0) + 1
    st.session_state["stream_loading"] = True


def _reset_filters() -> None:
    st.session_state.update(
        f_region="Все", f_vector="Все", f_sev="Low", f_search="", f_window="24ч"
    )


# --------------------------------------------------------------------------
# Live fragment: re-renders in isolation every 30 s, full rerun not needed.
# Seed advances with the 30 s wall-clock bucket, so each tick shows a fresh
# synthetic batch while staying reproducible for a given bucket.
# --------------------------------------------------------------------------
@st.fragment(run_every="30s")
def live_stream(region: str, vector: str, sev_floor: str, search: str, window_h: int, tick: int) -> None:
    head, ctl = st.columns([3, 1], gap="small")
    with head:
        st.subheader("Live-лента", anchor=False)
        st.caption("Автообновление каждые 30 с. Sample data.")
    with ctl:
        st.button(
            "Обновить поток",
            icon=":material/refresh:",
            on_click=_bump_stream,
            key="stream_refresh",
        )
    if st.session_state.get("stream_loading", False):
        st.skeleton(height=280)
    try:
        bucket = int(datetime.now(timezone.utc).timestamp() // 30)
        fresh = load_alerts(600, SEED_DEFAULT + tick + bucket, 48)
        fresh = apply_closed(fresh, list(st.session_state.get("closed_ids", [])))
        view = filter_alerts(fresh, region, vector, sev_floor, search, window_h)
    except (ValueError, KeyError) as exc:
        st.error(f"Не удалось обновить ленту: {exc}", icon=":material/error:")
        st.caption("Нажмите «Обновить поток» ещё раз — генератор локальный, следующая корзина уже готова.")
        return
    finally:
        st.session_state["stream_loading"] = False
    if view.empty:
        st.info("В live-ленте пока пусто для этих фильтров.", icon=":material/filter_alt_off:")
        return
    cols = ["detected_at", "severity", "technique_id", "attack_type", "src_ip", "country", "status"]
    st.dataframe(
        view[cols].head(8),
        hide_index=True,
        column_config={
            "detected_at": st.column_config.DatetimeColumn("Время", format="HH:mm:ss"),
            "severity": st.column_config.TextColumn("Severity"),
            "technique_id": st.column_config.TextColumn("Техника"),
            "attack_type": st.column_config.TextColumn("Вектор"),
            "src_ip": st.column_config.TextColumn("Источник"),
            "country": st.column_config.TextColumn("Страна"),
            "status": st.column_config.TextColumn("Статус"),
        },
        key="live_feed",
    )


@st.dialog("Подтверждение закрытия", icon=":material/warning:")
def confirm_close(alert_id: str) -> None:
    st.write(f"Инцидент {alert_id} будет переведён в статус Closed.")
    st.caption("Действие фиксируется в session_state текущей вкладки и не затрагивает других операторов.")
    c1, c2 = st.columns(2)
    if c1.button("Закрыть", type="primary", icon=":material/check_circle:"):
        closed = list(st.session_state.get("closed_ids", []))
        if alert_id not in closed:
            closed.append(alert_id)
        st.session_state["closed_ids"] = closed
        st.rerun()
    if c2.button("Отмена", icon=":material/cancel:"):
        st.rerun()


def _incident_detail(row: pd.Series) -> None:
    sev = str(row["severity"])
    st.write(f"{SEV_ICON.get(sev, '')} Severity: {sev} · CVSS {row['cvss']:.1f} · уверенность {int(row['confidence'])}")
    d1, d2, d3 = st.columns(3)
    d1.write(f"Техника: {row['technique_id']}")
    d2.write(f"Тактика: {row['tactic']}")
    d3.write(f"Вектор: {row['attack_type']}")
    n1, n2, n3 = st.columns(3)
    n1.write(f"Источник: {row['src_ip']} ({row['src_asn']}, {row['country']})")
    n2.write(f"Цель: {row['dst_asset']}:{int(row['dst_port'])}")
    n3.write(f"CVE: {row['cve_id'] or '—'} · статус {row['status']}")
    st.caption("Шкала: обнаружение → разбор → локализация → закрытие.")
    raw = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{row['alert_id'].lower()}",
        "created": pd.Timestamp(row["detected_at"]).isoformat(),
        "confidence": int(row["confidence"]),
        "pattern": f"[ipv4-addr:value = '{row['src_ip']}']",
        "labels": [row["attack_type"], row["tactic"]],
        "external_references": [{"source_name": "cve", "external_id": row["cve_id"]}] if row["cve_id"] else [],
        "x_misp_category": "Network activity",
        "x_misp_value": row["src_ip"],
        "synthetic": True,
    }
    st.code(json.dumps(raw, ensure_ascii=False, indent=2), language="json")


def main() -> None:
    # 1. FIRST st.* call. Once per page.
    st.set_page_config(
        page_title="SOC Console",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get help": "https://docs.streamlit.io",
            "Report a bug": "https://github.com/streamlit/streamlit/issues",
            "About": "SOC Console — sample data, Streamlit 1.64.0",
        },
    )

    # 2. Theme CSS, once, in one block. Palette itself lives in config.toml.
    st.html(CSS)

    if "closed_ids" not in st.session_state:
        st.session_state["closed_ids"] = []
    if "stream_tick" not in st.session_state:
        st.session_state["stream_tick"] = 0
    if "stream_loading" not in st.session_state:
        st.session_state["stream_loading"] = False

    with st.sidebar:
        st.header("Фильтры")
        st.caption("Фильтры применяются одной кнопкой: один реран на submit.")

    # 3. Input collection. A form turns every keystroke into one submit.
    with st.sidebar:
        with st.form("filters", border=False):
            region = st.selectbox("Регион", ["Все", "EU", "NA", "APAC", "LATAM", "MEA"], key="f_region")
            vector = st.selectbox("Тип атаки", ["Все", *VECTORS], key="f_vector")
            sev_floor = st.select_slider("Severity от", ["Low", "Medium", "High", "Critical"], value="Low", key="f_sev")
            search = st.text_input("Поиск: IP, CVE, техника", value="", key="f_search")
            window = st.radio("Окно", ["6ч", "24ч", "48ч"], index=1, horizontal=True, key="f_window")
            st.form_submit_button("Применить")
    window_h = WINDOW_H.get(window, 24)
    tick = int(st.session_state.get("stream_tick", 0))

    st.title("SOC Console", anchor=False)
    st.caption("Мониторинг угроз. Sample data — весь поток синтезирован локально и не является реальными инцидентами.")

    # 4. Data. Validate BEFORE the expensive call, not after.
    try:
        df = load_alerts(600, SEED_DEFAULT + tick, 48)
        df = apply_closed(df, list(st.session_state.get("closed_ids", [])))
    except (ValueError, KeyError) as exc:
        st.error(f"Не удалось построить поток алертов: {exc}", icon=":material/error:")
        with st.expander("Технические детали"):
            st.exception(exc)
        st.caption("Восстановление: нажмите «Применить» в панели фильтров — генератор пересоздаст корзину локально.")
        st.stop()

    view = filter_alerts(df, region, vector, sev_floor, search, window_h)

    if view.empty:
        st.info("Нет алертов под эти фильтры. Ослабьте severity или расширьте окно.", icon=":material/filter_alt_off:")
        st.button("Сбросить фильтры", on_click=_reset_filters, icon=":material/refresh:")
        st.stop()

    kpis = cached_kpis(view)

    # 5. KPI row. border=True only here: elevation marks the cockpit dials.
    k1, k2, k3, k4 = st.columns(4, gap="small")
    k1.metric(
        "Открытые инциденты", f"{kpis['open']}",
        delta=f"+{kpis['new_24h']} за 24ч",
        border=True, chart_data=kpis["sparks"]["open"], chart_type="line",
    )
    k2.metric(
        "Critical за 24ч", f"{kpis['crit_24h']}",
        delta="требуют разбора" if kpis["crit_24h"] else "чисто",
        border=True, chart_data=kpis["sparks"]["crit"], chart_type="line",
    )
    mttr_h = kpis["mttr"] / 60
    k3.metric(
        "MTTR (sample)", f"{mttr_h:.1f} ч" if mttr_h >= 1 else f"{kpis['mttr']:.0f} мин",
        delta=f"по {kpis['closed_n']} закрытым",
        border=True, chart_data=kpis["sparks"]["all"], chart_type="line",
    )
    k4.metric(
        "Активные источники", f"{kpis['sources']}",
        delta="уникальных IP",
        border=True, chart_data=kpis["sparks"]["src"], chart_type="line",
    )

    # 6. Content. 2:1 split, hero trend left, breakdown right.
    hero, side = st.columns([2, 1], gap="small")
    with hero:
        st.subheader("Тренд атак, 24ч", anchor=False)
        trend = cached_trend(view, 24)
        st.line_chart(trend.set_index("hour"), x_label="Время", y_label="Алерты")
    with side:
        st.subheader("По векторам", anchor=False)
        br = cached_breakdown(view)
        st.bar_chart(br, x="attack_type", y="count", horizontal=True, color="#FF7A18", x_label="Алерты", y_label="Вектор")

    # Live fragment: isolated reruns every 30 s.
    live_stream(region, vector, sev_floor, search, window_h, tick)

    # 7. Dense alert table. Selection is read from session_state: key mandatory.
    st.subheader("Алерты", divider=True, anchor=False)
    st.dataframe(
        view[["detected_at", "severity", "technique_id", "attack_type", "src_ip", "country", "cve_id", "confidence", "status"]].head(200),
        hide_index=True,
        column_config={
            "detected_at": st.column_config.DatetimeColumn("Обнаружен", format="DD.MM HH:mm"),
            "severity": st.column_config.TextColumn("Severity"),
            "technique_id": st.column_config.TextColumn("Техника"),
            "attack_type": st.column_config.TextColumn("Вектор"),
            "src_ip": st.column_config.TextColumn("Источник"),
            "country": st.column_config.TextColumn("Страна"),
            "cve_id": st.column_config.TextColumn("CVE"),
            "confidence": st.column_config.NumberColumn("Уверенность", format="%d"),
            "status": st.column_config.TextColumn("Статус"),
        },
        on_select="rerun",
        selection_mode="single-row",
        key="alerts",
    )

    sel = st.session_state.get("alerts")
    rows: list[int] = []
    if sel is not None:
        try:
            rows = list(sel.selection.rows)
        except (AttributeError, TypeError):
            rows = []
    target = view.iloc[rows[0]] if rows else view.iloc[0]

    # NOTE: no icon= here on purpose -- st.expander(icon=...) renders in the
    # browser but AppTest 1.64.0 does not record it (verified live), and the
    # incident detail must stay assertable. Icons live on buttons/dialogs.
    with st.expander(f"Инцидент {target['alert_id']}", expanded=False):
        _incident_detail(target)
        already = str(target["status"]) == "Closed"
        if st.button(
            "Закрыть инцидент",
            icon=":material/check_circle:",
            disabled=already,
            key="close_incident",
        ):
            confirm_close(str(target["alert_id"]))
        if already:
            st.caption("Инцидент уже закрыт — повторное подтверждение не требуется.")

    st.divider()
    st.caption(
        f"Поток кэширован на 60 с, агрегаты на 120 с. "
        f"Режим: {console_mode()} (переменная окружения SOC_MODE)."
    )


# No `if __name__ == "__main__"` server start here on purpose: AppTest
# executes this file as __main__, and a second st.App().run() inside a test
# runtime raises "A Streamlit server is already running in this process".
# The server is started by main.py only.
main()
