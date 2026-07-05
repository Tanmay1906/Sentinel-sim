"""
Service layer for executing detection rules, mapping alerts to MITRE ATT&CK, and logging indicators.
"""
import json
import uuid
import time
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from loguru import logger
from app.services.elasticsearch_service import ElasticsearchService

# --- Helper Utilities ---

def parse_timestamp(ts_val: Any) -> datetime:
    """Safely parses datetime values or ISO format strings to timezone-aware datetimes."""
    if isinstance(ts_val, datetime):
        return ts_val
    if isinstance(ts_val, str):
        if ts_val.endswith("Z"):
            ts_val = ts_val[:-1] + "+00:00"
        return datetime.fromisoformat(ts_val)
    return datetime.now()


# --- Detection Rule Engine ---

class BaseDetectionRule(ABC):
    """
    Abstract base class for all Sentinel-Sim threat detection rules.
    """
    def __init__(self, rule_id: str, rule_name: str, severity: str, mitre_tactic: str, mitre_technique: str):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique

    @abstractmethod
    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        """
        Evaluates events and returns list of generated Alert match dictionaries.
        """
        pass


# --- Concrete Rules Implementation ---

class WindowsBruteForceRule(BaseDetectionRule):
    """Rule 1: Detect Windows failed logon brute force attempts."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-001",
            rule_name="Windows Credential Brute Force",
            severity="high",
            mitre_tactic="Credential Access",
            mitre_technique="T1110"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        failed_logons = []
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4625:
                failed_logons.append(e)
                
        grouped = {}
        for e in failed_logons:
            host = e.get("host", {}).get("hostname", "unknown")
            user = e.get("user", {}).get("name", "unknown")
            key = (host, user)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(e)
            
        alerts = []
        for (host, user), user_events in grouped.items():
            user_events.sort(key=lambda x: parse_timestamp(x.get("timestamp")))
            
            for i in range(len(user_events) - 4):
                window = user_events[i:i+5]
                t_first = parse_timestamp(window[0].get("timestamp"))
                t_last = parse_timestamp(window[-1].get("timestamp"))
                diff = (t_last - t_first).total_seconds()
                if diff <= 120:
                    alerts.append({
                        "title": f"Credential Brute Force Activity on {host}",
                        "description": f"Detected 5 or more failed logon attempts for user '{user}' on host '{host}' within 2 minutes.",
                        "host": window[0].get("host"),
                        "user": window[0].get("user"),
                        "source_event_ids": [uuid.UUID(x.get("id")) for x in window],
                        "raw_matches": window
                    })
                    break
        return alerts


class LoginAfterFailuresRule(BaseDetectionRule):
    """Rule 2: Detect successful login shortly after failures for the same user on same host."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-002",
            rule_name="Successful Login After Failures",
            severity="critical",
            mitre_tactic="Initial Access",
            mitre_technique="T1078"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        grouped = {}
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id in (4624, 4625):
                host = e.get("host", {}).get("hostname", "unknown")
                user = e.get("user", {}).get("name", "unknown")
                key = (host, user)
                if key not in grouped:
                    grouped[key] = []
                grouped[key].append(e)
                
        alerts = []
        for (host, user), user_events in grouped.items():
            user_events.sort(key=lambda x: parse_timestamp(x.get("timestamp")))
            
            for i, e in enumerate(user_events):
                win_id = e.get("custom_fields", {}).get("winlog_event_id")
                if win_id == 4624:
                    t_success = parse_timestamp(e.get("timestamp"))
                    failures = []
                    for prev_e in user_events[:i]:
                        prev_win_id = prev_e.get("custom_fields", {}).get("winlog_event_id")
                        if prev_win_id == 4625:
                            t_fail = parse_timestamp(prev_e.get("timestamp"))
                            diff = (t_success - t_fail).total_seconds()
                            if 0 <= diff <= 300:
                                failures.append(prev_e)
                    if len(failures) >= 1:
                        alerts.append({
                            "title": f"Successful Login After Failures on {host}",
                            "description": f"User '{user}' successfully logged in on host '{host}' after {len(failures)} failed attempt(s) within 5 minutes.",
                            "host": e.get("host"),
                            "user": e.get("user"),
                            "source_event_ids": [uuid.UUID(x.get("id")) for x in failures + [e]],
                            "raw_matches": failures + [e]
                        })
                        break
        return alerts


class SuspiciousPowerShellRule(BaseDetectionRule):
    """Rule 3: Detect highly suspicious PowerShell execution parameters."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-003",
            rule_name="Suspicious PowerShell Command",
            severity="medium",
            mitre_tactic="Execution",
            mitre_technique="T1059.001"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        keywords = ["invoke-webrequest", "iex", "downloadstring", "encodedcommand"]
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4104:
                raw_log = e.get("raw_log", "").lower()
                matched_kw = [kw for kw in keywords if kw in raw_log]
                if matched_kw:
                    alerts.append({
                        "title": "Suspicious PowerShell Execution",
                        "description": f"PowerShell script block logging detected suspicious execution containing keyword(s): {', '.join(matched_kw)}.",
                        "host": e.get("host"),
                        "user": e.get("user"),
                        "source_event_ids": [uuid.UUID(e.get("id"))],
                        "raw_matches": [e]
                    })
        return alerts


class MimikatzRule(BaseDetectionRule):
    """Rule 4: Detect Mimikatz usage command lines."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-004",
            rule_name="Mimikatz Credentials Dump",
            severity="critical",
            mitre_tactic="Credential Access",
            mitre_technique="T1003"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        keywords = ["mimikatz", "sekurlsa", "logonpasswords"]
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4688:
                cmd_line = e.get("process", {}).get("command_line", "").lower()
                matched_kw = [kw for kw in keywords if kw in cmd_line]
                if matched_kw:
                    alerts.append({
                        "title": "Mimikatz Credential Dumping Activity",
                        "description": f"Process execution Command Line contains Mimikatz keyword(s): {', '.join(matched_kw)}.",
                        "host": e.get("host"),
                        "user": e.get("user"),
                        "source_event_ids": [uuid.UUID(e.get("id"))],
                        "raw_matches": [e]
                    })
        return alerts


class NewLocalAdminRule(BaseDetectionRule):
    """Rule 5: Detect local admin backdoor users creation."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-005",
            rule_name="New Local Admin Created",
            severity="high",
            mitre_tactic="Persistence",
            mitre_technique="T1136.001"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        creations = []
        additions = []
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4720:
                creations.append(e)
            elif win_id == 4732:
                additions.append(e)
                
        alerts = []
        for c in creations:
            c_host = c.get("host", {}).get("hostname", "unknown")
            c_user = c.get("custom_fields", {}).get("target_user")
            t_create = parse_timestamp(c.get("timestamp"))
            
            for a in additions:
                a_host = a.get("host", {}).get("hostname", "unknown")
                a_member = a.get("custom_fields", {}).get("member_name")
                a_group = a.get("custom_fields", {}).get("group_name", "")
                t_add = parse_timestamp(a.get("timestamp"))
                
                if c_host == a_host and c_user == a_member and a_group.lower() == "administrators":
                    diff = (t_add - t_create).total_seconds()
                    if 0 <= diff <= 300:
                        alerts.append({
                            "title": f"Backdoor Admin User Created on {c_host}",
                            "description": f"User account '{c_user}' was created and added to the Administrators local group within 5 minutes.",
                            "host": c.get("host"),
                            "user": c.get("user"),
                            "source_event_ids": [uuid.UUID(c.get("id")), uuid.UUID(a.get("id"))],
                            "raw_matches": [c, a]
                        })
                        break
        return alerts


class ScheduledTaskRule(BaseDetectionRule):
    """Rule 6: Detect Scheduled Task registration."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-006",
            rule_name="Scheduled Task Registered",
            severity="medium",
            mitre_tactic="Persistence",
            mitre_technique="T1053.005"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4698:
                task_name = e.get("custom_fields", {}).get("task_name", "unknown")
                alerts.append({
                    "title": f"Scheduled Task Created on {e.get('host', {}).get('hostname')}",
                    "description": f"A scheduled task named '{task_name}' was registered.",
                    "host": e.get("host"),
                    "user": e.get("user"),
                    "source_event_ids": [uuid.UUID(e.get("id"))],
                    "raw_matches": [e]
                })
        return alerts


class ServiceInstallationRule(BaseDetectionRule):
    """Rule 7: Detect Service installation."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-007",
            rule_name="System Service Installed",
            severity="medium",
            mitre_tactic="Persistence",
            mitre_technique="T1543.003"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        for e in events:
            win_id = e.get("custom_fields", {}).get("winlog_event_id")
            if win_id == 4697:
                svc_name = e.get("custom_fields", {}).get("service_name", "unknown")
                alerts.append({
                    "title": f"New System Service Installed on {e.get('host', {}).get('hostname')}",
                    "description": f"A new system service named '{svc_name}' was installed.",
                    "host": e.get("host"),
                    "user": e.get("user"),
                    "source_event_ids": [uuid.UUID(e.get("id"))],
                    "raw_matches": [e]
                })
        return alerts


class SSHBruteForceRule(BaseDetectionRule):
    """Rule 8: Detect SSH brute force logon attempts (Linux)."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-008",
            rule_name="SSH Brute Force",
            severity="high",
            mitre_tactic="Credential Access",
            mitre_technique="T1110"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        failed_logons = []
        for e in events:
            if e.get("log_source") == "auth_log" and e.get("event_type") == "authentication_failure":
                failed_logons.append(e)
                
        grouped = {}
        for e in failed_logons:
            host = e.get("host", {}).get("hostname", "unknown")
            user = e.get("user", {}).get("name", "unknown")
            key = (host, user)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(e)
            
        alerts = []
        for (host, user), user_events in grouped.items():
            user_events.sort(key=lambda x: parse_timestamp(x.get("timestamp")))
            
            for i in range(len(user_events) - 4):
                window = user_events[i:i+5]
                t_first = parse_timestamp(window[0].get("timestamp"))
                t_last = parse_timestamp(window[-1].get("timestamp"))
                diff = (t_last - t_first).total_seconds()
                if diff <= 120:
                    alerts.append({
                        "title": f"SSH Brute Force on {host}",
                        "description": f"Detected 5 or more failed SSH logon attempts for user '{user}' on host '{host}' within 2 minutes.",
                        "host": window[0].get("host"),
                        "user": window[0].get("user"),
                        "source_event_ids": [uuid.UUID(x.get("id")) for x in window],
                        "raw_matches": window
                    })
                    break
        return alerts


class ImpactRansomwareRule(BaseDetectionRule):
    """Rule 9: Detect backup deletions and system recovery invalidations (Ransomware patterns)."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-009",
            rule_name="Shadow Copies Deletion Activity",
            severity="critical",
            mitre_tactic="Impact",
            mitre_technique="T1490"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        for e in events:
            cmd_line = ""
            if e.get("custom_fields", {}).get("winlog_event_id") == 4688:
                cmd_line = e.get("process", {}).get("command_line", "").lower()
            elif e.get("log_source") == "auth_log" and e.get("event_type") == "elevation":
                cmd_line = e.get("process", {}).get("command_line", "").lower()
            elif e.get("log_source") == "auditd":
                cmd_line = (e.get("process", {}).get("command_line") or e.get("raw_log") or "").lower()
                
            if not cmd_line:
                continue
                
            if "vssadmin delete shadows" in cmd_line or "wbadmin delete" in cmd_line or "cipher.exe" in cmd_line:
                alerts.append({
                    "title": "System Recovery Invalidation and Ransomware Indicators",
                    "description": f"Suspicious recovery deletion command: '{cmd_line}' executed on {e.get('host', {}).get('hostname')}.",
                    "host": e.get("host"),
                    "user": e.get("user"),
                    "source_event_ids": [uuid.UUID(e.get("id"))],
                    "raw_matches": [e]
                })
        return alerts


class ExfiltrationRule(BaseDetectionRule):
    """Rule 10: Detect exfiltration tools and LOLBins execution."""
    def __init__(self):
        super().__init__(
            rule_id="RULE-010",
            rule_name="Alternative Data Exfiltration",
            severity="medium",
            mitre_tactic="Exfiltration",
            mitre_technique="T1048.003"
        )

    def evaluate(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        alerts = []
        lolbins = ["curl", "scp", "rsync", "bitsadmin", "certutil"]
        for e in events:
            cmd_line = ""
            if e.get("custom_fields", {}).get("winlog_event_id") == 4688:
                cmd_line = e.get("process", {}).get("command_line", "").lower()
            elif e.get("log_source") == "auth_log" and e.get("event_type") == "elevation":
                cmd_line = e.get("process", {}).get("command_line", "").lower()
                
            if not cmd_line:
                continue
                
            matched_bin = [b for b in lolbins if b in cmd_line]
            if matched_bin:
                alerts.append({
                    "title": "Data Exfiltration Tool Execution",
                    "description": f"Potential exfiltration tool execution '{cmd_line}' using lolbin: {', '.join(matched_bin)}.",
                    "host": e.get("host"),
                    "user": e.get("user"),
                    "source_event_ids": [uuid.UUID(e.get("id"))],
                    "raw_matches": [e]
                })
        return alerts


# --- Detection Service ---

class DetectionService:
    """
    Evaluates rule criteria against simulation logs and stores SOC alerts.
    """
    def __init__(self, es_service: ElasticsearchService):
        self.es = es_service
        # Stored alert logs path
        self.data_dir = Path(__file__).resolve().parents[2] / "data" / "alerts"
        
        # Rule registry
        self.rules: List[BaseDetectionRule] = [
            WindowsBruteForceRule(),
            LoginAfterFailuresRule(),
            SuspiciousPowerShellRule(),
            MimikatzRule(),
            NewLocalAdminRule(),
            ScheduledTaskRule(),
            ServiceInstallationRule(),
            SSHBruteForceRule(),
            ImpactRansomwareRule(),
            ExfiltrationRule()
        ]

    def evaluate_rules(self, events: List[Dict[str, Any]], simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Processes rules against events and collects match payloads."""
        matches = []
        for rule in self.rules:
            try:
                rule_matches = rule.evaluate(events, simulation_id)
                for m in rule_matches:
                    matches.append((rule, m))
            except Exception as exc:
                logger.error(f"Rule {rule.rule_id} threw an execution exception: {exc}")
        return matches

    def generate_alert(self, rule: BaseDetectionRule, match: Dict[str, Any], simulation_id: uuid.UUID) -> Dict[str, Any]:
        """Constructs a structured alert dictionary from a rule match."""
        return {
            "alert_id": uuid.uuid4(),
            "simulation_id": simulation_id,
            "timestamp": datetime.utcnow(),
            "title": match.get("title", rule.rule_name),
            "description": match.get("description", ""),
            "severity": rule.severity,
            "status": "new",
            "confidence": "high",
            "host": match.get("host"),
            "user": match.get("user"),
            "source_event_ids": match.get("source_event_ids", []),
            "mitre_tactic": rule.mitre_tactic,
            "mitre_technique": rule.mitre_technique,
            "rule_name": rule.rule_name,
            "rule_id": rule.rule_id,
            "raw_matches": match.get("raw_matches", [])
        }

    def run_detection(self, simulation_id: uuid.UUID, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Coordinates detection execution across all registered rules and matches.
        """
        start_time = time.perf_counter()
        
        # Evaluate
        matches = self.evaluate_rules(events, simulation_id)
        
        # Compile Alerts
        alerts = []
        for rule, match in matches:
            alerts.append(self.generate_alert(rule, match, simulation_id))
            
        duration = time.perf_counter() - start_time
        logger.bind(
            simulation_id=str(simulation_id),
            rules_executed=len(self.rules),
            alerts_created=len(alerts),
            detection_duration_s=duration
        ).info(f"Rules executed: {len(self.rules)} rules run, matched {len(alerts)} alerts in {duration:.4f}s.")
        
        return alerts

    def save_alerts(self, simulation_id: uuid.UUID, alerts: List[Dict[str, Any]]) -> None:
        """Saves generated alerts to backend/data/alerts/<simulation_id>.json."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        file_path = self.data_dir / f"{simulation_id}.json"
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, default=str, indent=4)
            
        logger.bind(
            simulation_id=str(simulation_id),
            alerts_stored=len(alerts)
        ).info(f"Alerts Saved: Stored {len(alerts)} alerts to file {file_path.name}")

    def load_alerts(self, simulation_id: uuid.UUID) -> List[Dict[str, Any]]:
        """Loads alerts for a specific simulation_id."""
        file_path = self.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            return []
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def delete_alerts(self, simulation_id: uuid.UUID) -> bool:
        """Deletes alerts associated with a simulation_id."""
        file_path = self.data_dir / f"{simulation_id}.json"
        if not file_path.exists():
            return False
        file_path.unlink()
        logger.bind(simulation_id=str(simulation_id)).info("Delete Request: Simulation alerts deleted from storage")
        return True

    def list_simulations_with_alerts(self) -> List[uuid.UUID]:
        """Lists all simulation IDs that have stored alerts."""
        if not self.data_dir.exists():
            return []
        simulations = []
        for file in self.data_dir.glob("*.json"):
            try:
                simulations.append(uuid.UUID(file.stem))
            except ValueError:
                pass
        return simulations

    def get_alert(self, simulation_id: uuid.UUID, alert_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves a single specific alert matching the ID."""
        alerts = self.load_alerts(simulation_id)
        for alert in alerts:
            if alert.get("alert_id") == str(alert_id):
                return alert
        return None

    def search_alerts(
        self,
        simulation_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        rule_name: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Searches generated threat detection alerts across stored alerts."""
        logger.bind(
            simulation_id=str(simulation_id) if simulation_id else None,
            severity=severity,
            rule_name=rule_name,
            limit=limit
        ).info("Search Requests: Querying alert logs")

        sim_ids = [simulation_id] if simulation_id else self.list_simulations_with_alerts()
        
        matches = []
        for sim_id in sim_ids:
            alerts = self.load_alerts(sim_id)
            for alert in alerts:
                if severity and alert.get("severity", "").lower() != severity.lower():
                    continue
                if rule_name and rule_name.lower() not in alert.get("rule_name", "").lower():
                    continue
                matches.append(alert)
                if len(matches) >= limit:
                    return matches
        return matches
