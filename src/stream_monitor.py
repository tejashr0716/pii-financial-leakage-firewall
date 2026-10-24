import json
import time
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
import httpx
from src.config import settings
from src.models import LeakageFinding, StreamMonitorResult
from src.detector import dlp_detector
from src.database import db

logger = logging.getLogger(__name__)


class GitHubStreamMonitor:
    """Continuously monitors public event streams for accidental credential and financial PII leakage."""

    def __init__(self):
        self.api_url = settings.GITHUB_EVENTS_API_URL

    async def scan_live_events(self, sample_count: int = 10, request_id: str = "stream-poll") -> StreamMonitorResult:
        start_t = time.perf_counter()
        headers = {
            "User-Agent": "FinancialLeakageFirewall/1.0 (dlp-security@compliance.internal)",
            "Accept": "application/vnd.github.v3+json"
        }

        events = []
        try:
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS) as client:
                resp = await client.get(self.api_url, headers=headers)
                if resp.status_code == 200:
                    events = resp.json()[:sample_count]
                else:
                    logger.warning("GitHub events API returned status %d. Using fallback sample.", resp.status_code)
                    events = self._get_fallback_events(sample_count)
        except Exception as e:
            logger.warning("GitHub events stream connection failed: %s. Using fallback sample.", e)
            events = self._get_fallback_events(sample_count)

        total_bytes = 0
        all_findings: List[LeakageFinding] = []

        for ev in events:
            raw_text = json.dumps(ev)
            total_bytes += len(raw_text.encode("utf-8"))
            findings = dlp_detector.scan_text(raw_text)
            if findings:
                all_findings.extend(findings)
                await db.record_findings(findings, request_id=request_id, source=f"GITHUB_EVENT_{ev.get('id', 'unknown')}")

        duration = time.perf_counter() - start_t

        return StreamMonitorResult(
            events_scanned=len(events),
            payload_bytes_scanned=total_bytes,
            leakages_detected=len(all_findings),
            findings=all_findings,
            duration_seconds=round(duration, 3)
        )

    def _get_fallback_events(self, count: int) -> List[Dict[str, Any]]:
        return [
            {
                "id": f"evt-{i}",
                "type": "PushEvent",
                "repo": {"name": f"public-repo-{i}/financial-app"},
                "payload": {
                    "commits": [
                        {"message": f"Update configuration and release candidate {i}"}
                    ]
                }
            }
            for i in range(count)
        ]


stream_monitor = GitHubStreamMonitor()
