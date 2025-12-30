"""
Threat Response System - Automated responses to detected phishing threats.
Includes quarantine, blocking, alerting, and audit logging.
"""

from enum import Enum
from datetime import datetime
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat classification levels"""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ResponseAction(Enum):
    """Automated response actions"""

    QUARANTINE = "quarantine"  # Move to spam/quarantine
    BLOCK = "block"  # Block sender/domain
    ALERT = "alert"  # Send security alert
    LOG = "log"  # Log for audit trail
    WHITELIST = "whitelist"  # Add to whitelist
    BLACKLIST = "blacklist"  # Add to blacklist


class ResponseHandler:
    """
    Handles automated responses to phishing threats.
    Implements policies for different threat levels.
    """

    def __init__(self, db=None):
        self.db = db
        self.response_log = []

    def handle_threat(
        self,
        threat_classification: str,
        threat_confidence: float,
        detection_data: Dict,
        sender: str = "",
        url: str = "",
        recipient: str = "",
    ) -> Dict:
        """
        Main method to handle detected threats with appropriate responses.

        Args:
            threat_classification: 'safe', 'suspicious', or 'malicious'
            threat_confidence: Confidence score (0-1)
            detection_data: Full detection data and features
            sender: Email sender or SMS originator
            url: URL if applicable
            recipient: Target email address

        Returns:
            Response result with actions taken
        """

        response = {
            "timestamp": datetime.now().isoformat(),
            "threat_classification": threat_classification,
            "threat_confidence": threat_confidence,
            "actions_taken": [],
            "status": "processed",
        }

        # Route to appropriate handler based on threat level
        if threat_classification == ThreatLevel.MALICIOUS.value:
            response["actions_taken"] = self._handle_malicious(
                detection_data, sender, url, recipient
            )

        elif threat_classification == ThreatLevel.SUSPICIOUS.value:
            response["actions_taken"] = self._handle_suspicious(
                detection_data, sender, url, recipient, threat_confidence
            )

        elif threat_classification == ThreatLevel.SAFE.value:
            response["actions_taken"] = [ResponseAction.LOG.value]

        # Log the response
        self._log_response(response)

        return response

    def _handle_malicious(
        self, detection_data: Dict, sender: str, url: str, recipient: str
    ) -> List[str]:
        """Handle malicious threats - highest priority response"""

        actions = []

        # Always quarantine
        actions.append(ResponseAction.QUARANTINE.value)
        self._quarantine_message(recipient, sender)

        # Block sender and domain
        if sender:
            actions.append(ResponseAction.BLOCK.value)
            self._block_sender(sender)

        if url:
            self._block_domain(url)

        # Add to blacklist
        if sender:
            actions.append(ResponseAction.BLACKLIST.value)
            if self.db:
                self.db.add_blacklist(sender=sender)

        # Send immediate alert
        actions.append(ResponseAction.ALERT.value)
        self._send_security_alert(
            recipient,
            f"CRITICAL: Malicious phishing attempt detected",
            severity="critical",
        )

        # Log for audit
        actions.append(ResponseAction.LOG.value)

        logger.warning(
            f"[MALICIOUS] Blocked phishing attempt from {sender} to {recipient}"
        )

        return actions

    def _handle_suspicious(
        self,
        detection_data: Dict,
        sender: str,
        url: str,
        recipient: str,
        confidence: float,
    ) -> List[str]:
        """Handle suspicious threats - moderate response"""

        actions = []

        # Quarantine with high confidence
        if confidence > 0.7:
            actions.append(ResponseAction.QUARANTINE.value)
            self._quarantine_message(recipient, sender, severity="high")
            actions.append(ResponseAction.ALERT.value)
            self._send_security_alert(
                recipient,
                f"HIGH: Suspicious phishing attempt detected with {confidence*100:.0f}% confidence",
                severity="high",
            )

        # Quarantine with moderate confidence
        else:
            actions.append(ResponseAction.QUARANTINE.value)
            self._quarantine_message(recipient, sender, severity="moderate")
            actions.append(ResponseAction.ALERT.value)
            self._send_security_alert(
                recipient,
                f"WARNING: Suspicious content detected",
                severity="medium",
            )

        # Log for review
        actions.append(ResponseAction.LOG.value)

        logger.info(
            f"[SUSPICIOUS] Quarantined suspicious message from {sender} to {recipient}"
        )

        return actions

    def _quarantine_message(
        self, recipient: str, sender: str, severity: str = "moderate"
    ):
        """Move message to quarantine/spam folder"""
        action = {
            "action": "quarantine",
            "recipient": recipient,
            "sender": sender,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "reason": "Phishing threat detected",
        }
        # In production: actually move the message in email system
        logger.info(f"Quarantined message: {action}")

    def _block_sender(self, sender: str):
        """Add sender to block list"""
        action = {
            "action": "block_sender",
            "sender": sender,
            "timestamp": datetime.now().isoformat(),
        }
        logger.info(f"Blocked sender: {sender}")

    def _block_domain(self, url: str):
        """Extract and block domain from URL"""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            action = {
                "action": "block_domain",
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
            }
            logger.info(f"Blocked domain: {domain}")
        except Exception as e:
            logger.error(f"Error blocking domain: {e}")

    def _send_security_alert(self, recipient: str, message: str, severity: str = "medium"):
        """Send security alert to recipient"""
        alert = {
            "action": "security_alert",
            "recipient": recipient,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }
        # In production: send email alert to user
        logger.info(f"Sent alert: {alert}")

    def _log_response(self, response: Dict):
        """Log response for audit trail"""
        self.response_log.append(response)
        if self.db:
            self.db.store_response_log(response)

    def get_response_history(self, limit: int = 100) -> List[Dict]:
        """Get response history"""
        return self.response_log[-limit:]

    def get_blocked_senders(self) -> List[str]:
        """Get list of blocked senders"""
        if self.db:
            return list(self.db.blacklist)
        return []

    def get_quarantine_queue(self) -> List[Dict]:
        """Get messages in quarantine queue"""
        quarantined = [
            r
            for r in self.response_log
            if ResponseAction.QUARANTINE.value in r.get("actions_taken", [])
        ]
        return quarantined[-50:]  # Last 50


class PolicyManager:
    """
    Manages response policies for different threat scenarios.
    Allows customization of automated response behaviors.
    """

    def __init__(self):
        self.policies = {
            "malicious": {
                "auto_quarantine": True,
                "auto_block": True,
                "send_alert": True,
                "require_approval": False,
            },
            "suspicious": {
                "auto_quarantine": True,
                "auto_block": False,
                "send_alert": True,
                "require_approval": False,
            },
            "safe": {
                "auto_quarantine": False,
                "auto_block": False,
                "send_alert": False,
                "require_approval": False,
            },
        }

    def get_policy(self, threat_level: str) -> Dict:
        """Get policy for threat level"""
        return self.policies.get(threat_level, self.policies["safe"])

    def update_policy(self, threat_level: str, policy: Dict):
        """Update policy for threat level"""
        if threat_level in self.policies:
            self.policies[threat_level].update(policy)

    def should_require_approval(self, threat_level: str) -> bool:
        """Check if response requires manual approval"""
        policy = self.get_policy(threat_level)
        return policy.get("require_approval", False)

    def should_auto_quarantine(self, threat_level: str) -> bool:
        """Check if auto-quarantine is enabled"""
        policy = self.get_policy(threat_level)
        return policy.get("auto_quarantine", False)
