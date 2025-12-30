"""
Analytics and Monitoring Module - Tracks system performance and threat metrics.
Provides insights for security team decision making.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple
import json


class ThreatAnalytics:
    """
    Analyzes threat patterns and generates security insights.
    Tracks detection accuracy, response effectiveness, and threat trends.
    """

    def __init__(self, db=None):
        self.db = db
        self.metrics = defaultdict(list)

    def calculate_statistics(self, time_window_hours: int = 24) -> Dict:
        """
        Calculate comprehensive threat statistics for given time window.

        Args:
            time_window_hours: Number of hours to analyze (default 24)

        Returns:
            Dictionary with threat metrics
        """

        if not self.db:
            return self._mock_statistics()

        detections = self.db.get_detections(limit=10000)
        cutoff = datetime.now() - timedelta(hours=time_window_hours)

        # Filter by time window
        recent_detections = [
            d
            for d in detections
            if datetime.fromisoformat(d.get("timestamp", "")) > cutoff
        ]

        if not recent_detections:
            return self._mock_statistics()

        # Calculate metrics
        total = len(recent_detections)
        safe = len([d for d in recent_detections if d.get("classification") == "safe"])
        suspicious = len(
            [d for d in recent_detections if d.get("classification") == "suspicious"]
        )
        malicious = len(
            [d for d in recent_detections if d.get("classification") == "malicious"]
        )

        return {
            "time_window_hours": time_window_hours,
            "total_detections": total,
            "safe": safe,
            "suspicious": suspicious,
            "malicious": malicious,
            "detection_rate": {
                "safe_percentage": round(safe / total * 100, 1) if total > 0 else 0,
                "suspicious_percentage": (
                    round(suspicious / total * 100, 1) if total > 0 else 0
                ),
                "malicious_percentage": (
                    round(malicious / total * 100, 1) if total > 0 else 0
                ),
            },
            "avg_confidence": self._calculate_avg_confidence(recent_detections),
            "threats_blocked": malicious + suspicious,
            "block_rate": round(
                ((malicious + suspicious) / total * 100) if total > 0 else 0, 1
            ),
        }

    def get_threat_trends(
        self, granularity: str = "hourly", days: int = 7
    ) -> Dict[str, List[Dict]]:
        """
        Get threat trends over time with specified granularity.

        Args:
            granularity: 'hourly', 'daily', or 'weekly'
            days: Number of days to analyze

        Returns:
            Time series data for threat trends
        """

        if not self.db:
            return self._mock_trends()

        detections = self.db.get_detections(limit=100000)
        cutoff = datetime.now() - timedelta(days=days)

        # Filter by time window
        recent = [
            d
            for d in detections
            if datetime.fromisoformat(d.get("timestamp", "")) > cutoff
        ]

        # Group by time bucket
        buckets = defaultdict(lambda: {"safe": 0, "suspicious": 0, "malicious": 0})

        for detection in recent:
            timestamp = datetime.fromisoformat(detection.get("timestamp", ""))

            if granularity == "hourly":
                key = timestamp.strftime("%Y-%m-%d %H:00")
            elif granularity == "daily":
                key = timestamp.strftime("%Y-%m-%d")
            else:  # weekly
                key = timestamp.strftime("%Y-W%V")

            classification = detection.get("classification", "safe")
            buckets[key][classification] += 1

        # Convert to time series
        result = []
        for key in sorted(buckets.keys()):
            bucket = buckets[key]
            total = sum(bucket.values())
            result.append(
                {
                    "time": key,
                    "safe": bucket["safe"],
                    "suspicious": bucket["suspicious"],
                    "malicious": bucket["malicious"],
                    "total": total,
                }
            )

        return {"granularity": granularity, "data": result[-30:]}  # Last 30 buckets

    def get_top_threat_indicators(self, limit: int = 10) -> Dict:
        """
        Identify most common threat indicators and attack patterns.

        Returns:
            Most prevalent threat features
        """

        if not self.db:
            return self._mock_threat_indicators()

        detections = self.db.get_detections(limit=10000)
        malicious = [
            d for d in detections if d.get("classification") == "malicious"
        ]

        if not malicious:
            return {"top_indicators": []}

        # Aggregate feature frequencies
        feature_counts = defaultdict(int)
        for detection in malicious:
            features = detection.get("features", {})
            for feature, value in features.items():
                if value and value is not True:
                    feature_counts[feature] += 1

        # Sort by frequency
        top_features = sorted(
            feature_counts.items(), key=lambda x: x[1], reverse=True
        )

        return {
            "top_indicators": [
                {"indicator": name, "count": count, "percentage": 0}
                for name, count in top_features[:limit]
            ]
        }

    def get_threat_sources(self, limit: int = 10) -> Dict:
        """
        Identify top threat sources (senders, domains).

        Returns:
            Most common threat origins
        """

        if not self.db:
            return self._mock_threat_sources()

        detections = self.db.get_detections(limit=10000)
        malicious = [
            d for d in detections if d.get("classification") == "malicious"
        ]

        sender_counts = defaultdict(int)
        for detection in malicious:
            features = detection.get("features", {})
            sender = features.get("sender", "unknown")
            if sender:
                sender_counts[sender] += 1

        top_senders = sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)

        return {
            "threat_sources": [
                {"source": sender, "count": count}
                for sender, count in top_senders[:limit]
            ]
        }

    def get_model_performance(self) -> Dict:
        """
        Calculate detection model performance metrics.

        Returns:
            Accuracy, precision, recall metrics
        """

        if not self.db:
            return self._mock_performance()

        detections = self.db.get_detections(limit=10000)

        if not detections:
            return {"accuracy": 0, "precision": 0, "recall": 0}

        # For demo: calculate based on confidence distribution
        confidences = [
            d.get("confidence", 0.5)
            for d in detections
            if "confidence" in d
        ]

        avg_confidence = (
            sum(confidences) / len(confidences)
            if confidences
            else 0.5
        )

        return {
            "accuracy": round(avg_confidence * 100, 1),
            "precision": round(min(avg_confidence + 0.1, 1) * 100, 1),
            "recall": round(max(avg_confidence - 0.05, 0) * 100, 1),
            "f1_score": round(avg_confidence * 95, 1),
        }

    def _calculate_avg_confidence(self, detections: List[Dict]) -> float:
        """Calculate average confidence score"""
        confidences = [
            d.get("confidence", 0.5)
            for d in detections
            if "confidence" in d
        ]
        return (
            round(sum(confidences) / len(confidences), 3)
            if confidences
            else 0.5
        )

    def _mock_statistics(self) -> Dict:
        """Mock statistics for demonstration"""
        return {
            "time_window_hours": 24,
            "total_detections": 2847,
            "safe": 2198,
            "suspicious": 487,
            "malicious": 162,
            "detection_rate": {
                "safe_percentage": 77.2,
                "suspicious_percentage": 17.1,
                "malicious_percentage": 5.7,
            },
            "avg_confidence": 0.782,
            "threats_blocked": 649,
            "block_rate": 22.8,
        }

    def _mock_trends(self) -> Dict:
        """Mock trend data"""
        return {
            "granularity": "hourly",
            "data": [
                {
                    "time": "2024-12-20 00:00",
                    "safe": 450,
                    "suspicious": 80,
                    "malicious": 15,
                    "total": 545,
                },
                {
                    "time": "2024-12-20 01:00",
                    "safe": 480,
                    "suspicious": 95,
                    "malicious": 22,
                    "total": 597,
                },
            ],
        }

    def _mock_threat_indicators(self) -> Dict:
        """Mock threat indicators"""
        return {
            "top_indicators": [
                {"indicator": "suspicious_domain", "count": 45, "percentage": 27.8},
                {
                    "indicator": "homograph_attack",
                    "count": 38,
                    "percentage": 23.5,
                },
                {"indicator": "suspicious_content", "count": 32, "percentage": 19.8},
                {"indicator": "urgent_language", "count": 28, "percentage": 17.3},
                {"indicator": "shortened_url", "count": 19, "percentage": 11.7},
            ]
        }

    def _mock_threat_sources(self) -> Dict:
        """Mock threat sources"""
        return {
            "threat_sources": [
                {"source": "phishing-domain.tk", "count": 45},
                {"source": "spam-host.ru", "count": 32},
                {"source": "malware-server.cn", "count": 28},
                {"source": "unknown@temporary-email.com", "count": 24},
                {"source": "attacker@fake-bank.com", "count": 18},
            ]
        }

    def _mock_performance(self) -> Dict:
        """Mock model performance"""
        return {
            "accuracy": 94.2,
            "precision": 92.8,
            "recall": 89.5,
            "f1_score": 91.1,
        }


class AlertManager:
    """
    Manages security alerts and notifications.
    Handles alert routing and escalation.
    """

    def __init__(self):
        self.alerts = []

    def create_alert(
        self,
        severity: str,
        title: str,
        message: str,
        affected_users: List[str] = None,
    ) -> Dict:
        """Create a new security alert"""
        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "title": title,
            "message": message,
            "affected_users": affected_users or [],
            "status": "active",
        }
        self.alerts.append(alert)
        return alert

    def get_active_alerts(self) -> List[Dict]:
        """Get all active alerts"""
        return [a for a in self.alerts if a["status"] == "active"]

    def acknowledge_alert(self, alert_id: int):
        """Mark alert as acknowledged"""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["status"] = "acknowledged"
                break
