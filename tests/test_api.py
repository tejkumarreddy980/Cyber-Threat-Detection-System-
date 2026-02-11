from backend.app import create_app


def test_health_endpoint():
    app = create_app()
    client = app.test_client()

    response = client.get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


def test_detect_endpoint_flags_anomaly_like_input():
    app = create_app()
    client = app.test_client()

    response = client.post(
        "/detect",
        json={
            "flow": {
                "duration": 0.5,
                "src_bytes": 5,
                "dst_bytes": 3,
                "packets": 5000,
                "failed_logins": 3,
                "dst_port": 9999,
            }
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["label"] in {"normal", "anomaly"}
    assert "score" in payload
