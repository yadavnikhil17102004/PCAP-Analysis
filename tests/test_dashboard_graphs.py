from dashboard_app.dashboard import _build_network_graph

import pandas as pd


def test_network_graph_uses_readable_text_on_dark_theme():
    query_df = pd.DataFrame(
        [
            {
                "src": "192.168.1.10",
                "sld": "bad.example",
                "qname": "abcd1234.bad.example",
                "dga_score": 0.91,
            },
            {
                "src": "192.168.1.10",
                "sld": "bad.example",
                "qname": "efgh5678.bad.example",
                "dga_score": 0.88,
            },
        ]
    )
    ip_df = pd.DataFrame(
        [
            {"IP": "8.8.8.8", "Country": "United States", "ASN": "AS15169"},
            {"IP": "1.1.1.1", "Country": "Australia", "ASN": "AS13335"},
        ]
    )
    answer_map = {"bad.example": ["8.8.8.8", "1.1.1.1"]}

    fig = _build_network_graph(query_df, ip_df, answer_map, focus_domain="bad.example")

    assert fig.layout.font.color == "#e5eefc"
    text_traces = [trace for trace in fig.data if getattr(trace, "mode", "") == "markers+text"]
    assert text_traces, "expected labeled node traces"
    assert all(getattr(trace.textfont, "color", None) == "#e5eefc" for trace in text_traces)
