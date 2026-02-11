from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Flask, jsonify, request

from .detector import FEATURES, IntrusionDetector


def create_app() -> Flask:
    app = Flask(__name__)
    detector = IntrusionDetector()

    @app.get("/health")
    def health() -> Any:
        return jsonify(
            {
                "status": "ok",
                "service": "cyber-threat-detection-api",
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            }
        )

    @app.post("/detect")
    def detect() -> Any:
        payload = request.get_json(silent=True) or {}
        flow = payload.get("flow")
        if not isinstance(flow, dict):
            return jsonify({"error": "Request body must include a 'flow' object."}), 400

        result = detector.predict(flow)
        return jsonify(
            {
                "label": result.label,
                "score": result.score,
                "threshold": result.threshold,
                "features_used": FEATURES,
            }
        )

    @app.post("/detect/batch")
    def detect_batch() -> Any:
        payload = request.get_json(silent=True) or {}
        flows = payload.get("flows")
        if not isinstance(flows, list) or not all(isinstance(flow, dict) for flow in flows):
            return jsonify({"error": "Request body must include a 'flows' array of objects."}), 400

        results = detector.batch_predict(flows)
        response: List[Dict[str, Any]] = [
            {
                "index": index,
                "label": result.label,
                "score": result.score,
                "threshold": result.threshold,
            }
            for index, result in enumerate(results)
        ]
        return jsonify({"count": len(response), "results": response})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
