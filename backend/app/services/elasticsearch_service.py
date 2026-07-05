"""
Service interface and base logic for interacting with Elasticsearch 8.x index storage.
"""
import os
import uuid
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
# pyrefly: ignore [missing-import]
from loguru import logger

class ElasticsearchService:
    """
    Handles indexing of ECS log events and performing searches on Elasticsearch clusters.
    """
    def __init__(self):
        # Read from environment variables with defaults matching settings
        self.url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        self.username = os.getenv("ELASTICSEARCH_USERNAME") or os.getenv("ELASTICSEARCH_USER", "elastic")
        self.password = os.getenv("ELASTICSEARCH_PASSWORD")
        self.index_events = os.getenv("INDEX_EVENTS", "sentinel-events")
        self.index_alerts = os.getenv("INDEX_ALERTS", "sentinel-alerts")
        
        self.client = None
        self.is_active = False
        
        # Proactively trigger connection setup
        self.connect()

    def connect(self) -> bool:
        """Initializes the connection to the Elasticsearch cluster and pings it."""
        try:
            from elasticsearch import Elasticsearch
        except ImportError:
            logger.warning("elasticsearch package not installed. Elasticsearch operations disabled.")
            self.is_active = False
            return False

        try:
            kwargs = {}
            if self.username and self.password:
                kwargs["basic_auth"] = (self.username, self.password)
            
            # Short request timeout (3s) to prevent blocking application startup if ES is down
            self.client = Elasticsearch(self.url, request_timeout=3.0, **kwargs)
            
            if self.client.ping():
                self.is_active = True
                logger.info(f"Connected to Elasticsearch cluster at {self.url}")
                # Bootstrap index templates/mappings
                self.create_index(self.index_events)
                self.create_index(self.index_alerts)
                return True
            else:
                self.is_active = False
                logger.warning("Elasticsearch ping failed. Fallback to local JSON files active.")
                return False
        except Exception as exc:
            self.is_active = False
            logger.warning(f"Elasticsearch connection failed: {exc}. Fallback to local JSON files active.")
            return False

    def ping(self) -> bool:
        """Tests if the current Elasticsearch cluster connection is active."""
        if not self.client:
            return False
        try:
            return self.client.ping()
        except Exception:
            return False

    def create_index(self, index_name: str) -> None:
        """Checks if an index exists, and if not, creates it with mappings."""
        if not self.is_active or not self.client:
            return
        try:
            if self.client.indices.exists(index=index_name):
                return

            if index_name == self.index_events:
                mappings = {
                    "properties": {
                        "id": { "type": "keyword" },
                        "timestamp": { "type": "date" },
                        "event_category": { "type": "keyword" },
                        "event_type": { "type": "keyword" },
                        "log_source": { "type": "keyword" },
                        "raw_log": { "type": "text" },
                        "simulation_id": { "type": "keyword" },
                        "host": {
                            "properties": {
                                "hostname": { "type": "keyword" },
                                "ip": { "type": "ip" },
                                "os_family": { "type": "keyword" },
                                "criticality": { "type": "keyword" }
                            }
                        },
                        "user": {
                            "properties": {
                                "name": { "type": "keyword" },
                                "domain": { "type": "keyword" }
                            }
                        },
                        "custom_fields": {
                            "properties": {
                                "winlog_event_id": { "type": "integer" },
                                "logon_type": { "type": "integer" },
                                "task_name": { "type": "keyword" },
                                "service_name": { "type": "keyword" },
                                "target_user": { "type": "keyword" },
                                "member_name": { "type": "keyword" },
                                "group_name": { "type": "keyword" }
                            }
                        }
                    }
                }
            else:  # sentinel-alerts mapping
                mappings = {
                    "properties": {
                        "alert_id": { "type": "keyword" },
                        "simulation_id": { "type": "keyword" },
                        "timestamp": { "type": "date" },
                        "title": { "type": "keyword" },
                        "description": { "type": "text" },
                        "severity": { "type": "keyword" },
                        "status": { "type": "keyword" },
                        "confidence": { "type": "keyword" },
                        "mitre_tactic": { "type": "keyword" },
                        "mitre_technique": { "type": "keyword" },
                        "rule_name": { "type": "keyword" },
                        "rule_id": { "type": "keyword" },
                        "source_event_ids": { "type": "keyword" },
                        "host": {
                            "properties": {
                                "hostname": { "type": "keyword" },
                                "ip": { "type": "ip" },
                                "os_family": { "type": "keyword" },
                                "criticality": { "type": "keyword" }
                            }
                        },
                        "user": {
                            "properties": {
                                "name": { "type": "keyword" },
                                "domain": { "type": "keyword" }
                            }
                        }
                    }
                }
            self.client.indices.create(index=index_name, body={"mappings": mappings})
            logger.info(f"Created Elasticsearch mapping structure for index '{index_name}'")
        except Exception as exc:
            logger.error(f"Failed to create index {index_name}: {exc}")

    def bulk_index_events(self, simulation_id: uuid.UUID, events: List[Dict[str, Any]]) -> int:
        """Indexes bulk event documents to sentinel-events."""
        if not self.is_active or not self.client:
            return 0
        from elasticsearch.helpers import bulk
        start = time.perf_counter()
        
        actions = []
        for event in events:
            doc = dict(event)
            doc["simulation_id"] = str(simulation_id)
            actions.append({
                "_index": self.index_events,
                "_id": event.get("id"),
                "_source": doc
            })
            
        try:
            success, failed = bulk(self.client, actions)
            duration = time.perf_counter() - start
            logger.bind(
                simulation_id=str(simulation_id),
                events_indexed=success,
                latency_s=duration
            ).info(f"Elasticsearch: Bulk indexed {success} events in {duration:.4f}s.")
            return success
        except Exception as exc:
            logger.error(f"Bulk indexing events to Elasticsearch failed: {exc}")
            return 0

    def bulk_index_alerts(self, simulation_id: uuid.UUID, alerts: List[Dict[str, Any]]) -> int:
        """Indexes bulk alert documents to sentinel-alerts."""
        if not self.is_active or not self.client:
            return 0
        from elasticsearch.helpers import bulk
        start = time.perf_counter()
        
        actions = []
        for alert in alerts:
            actions.append({
                "_index": self.index_alerts,
                "_id": alert.get("alert_id"),
                "_source": alert
            })
            
        try:
            success, failed = bulk(self.client, actions)
            duration = time.perf_counter() - start
            logger.bind(
                simulation_id=str(simulation_id),
                alerts_indexed=success,
                latency_s=duration
            ).info(f"Elasticsearch: Bulk indexed {success} alerts in {duration:.4f}s.")
            return success
        except Exception as exc:
            logger.error(f"Bulk indexing alerts to Elasticsearch failed: {exc}")
            return 0

    def search_events(
        self,
        simulation_id: Optional[uuid.UUID] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        event_id: Optional[int] = None,
        platform: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Queries event logs from Elasticsearch sentinel-events index."""
        if not self.is_active or not self.client:
            raise RuntimeError("Elasticsearch is unavailable")

        must_queries = []
        if simulation_id:
            must_queries.append({"term": {"simulation_id": str(simulation_id)}})
        if host:
            must_queries.append({
                "bool": {
                    "should": [
                        {"term": {"host.hostname": host}},
                        {"term": {"host.ip": host}}
                    ]
                }
            })
        if user:
            must_queries.append({"term": {"user.name": user}})
        if event_id is not None:
            must_queries.append({"term": {"custom_fields.winlog_event_id": event_id}})
        if platform:
            must_queries.append({"term": {"host.os_family": platform}})
        if severity:
            must_queries.append({"term": {"host.criticality": severity}})
            
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time.isoformat()
            if end_time:
                time_range["lte"] = end_time.isoformat()
            must_queries.append({"range": {"timestamp": time_range}})
            
        query = {"bool": {"must": must_queries}} if must_queries else {"match_all": {}}
        
        try:
            start_t = time.perf_counter()
            response = self.client.search(
                index=self.index_events,
                query=query,
                from_=offset,
                size=limit,
                sort=[{"timestamp": "asc"}]
            )
            latency = time.perf_counter() - start_t
            logger.bind(latency_s=latency).debug("Elasticsearch search_events completed")
            
            hits = response["hits"]["hits"]
            return [hit["_source"] for hit in hits]
        except Exception as exc:
            logger.error(f"Elasticsearch search_events failed: {exc}")
            raise exc

    def search_alerts(
        self,
        simulation_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        rule_name: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Queries alerts from Elasticsearch sentinel-alerts index."""
        if not self.is_active or not self.client:
            raise RuntimeError("Elasticsearch is unavailable")

        must_queries = []
        if simulation_id:
            must_queries.append({"term": {"simulation_id": str(simulation_id)}})
        if severity:
            must_queries.append({"term": {"severity": severity}})
        if rule_name:
            must_queries.append({"match": {"rule_name": rule_name}})
        if mitre_technique:
            must_queries.append({"term": {"mitre_technique": mitre_technique}})
            
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time.isoformat()
            if end_time:
                time_range["lte"] = end_time.isoformat()
            must_queries.append({"range": {"timestamp": time_range}})
            
        query = {"bool": {"must": must_queries}} if must_queries else {"match_all": {}}
        
        try:
            start_t = time.perf_counter()
            response = self.client.search(
                index=self.index_alerts,
                query=query,
                from_=offset,
                size=limit,
                sort=[{"timestamp": "asc"}]
            )
            latency = time.perf_counter() - start_t
            logger.bind(latency_s=latency).debug("Elasticsearch search_alerts completed")
            
            hits = response["hits"]["hits"]
            return [hit["_source"] for hit in hits]
        except Exception as exc:
            logger.error(f"Elasticsearch search_alerts failed: {exc}")
            raise exc

    def delete_simulation(self, simulation_id: uuid.UUID) -> Dict[str, Any]:
        """Deletes all event and alert documents matching the simulation_id."""
        if not self.is_active or not self.client:
            return {"deleted": False}
        try:
            query = {"term": {"simulation_id": str(simulation_id)}}
            
            res_events = self.client.delete_by_query(index=self.index_events, query=query)
            res_alerts = self.client.delete_by_query(index=self.index_alerts, query=query)
            
            logger.info(f"Deleted simulation {simulation_id} documents from Elasticsearch.")
            return {
                "deleted": True,
                "events_deleted": res_events.get("deleted", 0),
                "alerts_deleted": res_alerts.get("deleted", 0)
            }
        except Exception as exc:
            logger.error(f"Elasticsearch delete_simulation failed: {exc}")
            return {"deleted": False, "error": str(exc)}

    def statistics(self) -> Dict[str, Any]:
        """Aggregates metrics across the event and alert indices (with fallback to local JSON)."""
        if not self.is_active or not self.client:
            # Local fallback stats calculation
            logger.info("Elasticsearch is inactive. Computing statistics from local fallback JSON storage.")
            from pathlib import Path
            import json
            
            # Paths
            events_dir = Path(__file__).resolve().parents[2] / "data" / "events"
            alerts_dir = Path(__file__).resolve().parents[2] / "data" / "alerts"
            
            total_events = 0
            total_alerts = 0
            events_by_platform = {}
            events_by_category = {}
            top_hosts = {}
            top_users = {}
            top_mitre_techniques = {}
            alerts_by_severity = {}
            alerts_by_rule = {}
            daily_timeline = {}
            
            # Aggregate events
            if events_dir.exists():
                for file in events_dir.glob("*.json"):
                    try:
                        with open(file, "r", encoding="utf-8") as f:
                            events = json.load(f)
                            total_events += len(events)
                            for e in events:
                                platform = e.get("host", {}).get("os_family", "unknown")
                                events_by_platform[platform] = events_by_platform.get(platform, 0) + 1
                                category = e.get("event_category", "unknown")
                                events_by_category[category] = events_by_category.get(category, 0) + 1
                                host = e.get("host", {}).get("hostname", "unknown")
                                top_hosts[host] = top_hosts.get(host, 0) + 1
                                user = e.get("user", {}).get("name", "unknown")
                                top_users[user] = top_users.get(user, 0) + 1
                    except Exception:
                        continue
                        
            # Aggregate alerts
            if alerts_dir.exists():
                for file in alerts_dir.glob("*.json"):
                    try:
                        with open(file, "r", encoding="utf-8") as f:
                            alerts = json.load(f)
                            total_alerts += len(alerts)
                            for a in alerts:
                                mitre = a.get("mitre_technique", "unknown")
                                top_mitre_techniques[mitre] = top_mitre_techniques.get(mitre, 0) + 1
                                severity = a.get("severity", "unknown")
                                alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
                                rule = a.get("rule_name", "unknown")
                                alerts_by_rule[rule] = alerts_by_rule.get(rule, 0) + 1
                                ts_str = a.get("timestamp", "")
                                if ts_str:
                                    date_key = ts_str.split("T")[0] if "T" in ts_str else ts_str.split(" ")[0]
                                    daily_timeline[date_key] = daily_timeline.get(date_key, 0) + 1
                    except Exception:
                        continue
                        
            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "events_by_platform": events_by_platform,
                "events_by_category": events_by_category,
                "top_hosts": top_hosts,
                "top_users": top_users,
                "top_mitre_techniques": top_mitre_techniques,
                "alerts_by_severity": alerts_by_severity,
                "alerts_by_rule": alerts_by_rule,
                "daily_timeline": daily_timeline
            }

        try:
            count_ev = self.client.count(index=self.index_events)["count"]
            count_al = self.client.count(index=self.index_alerts)["count"]
            
            aggs_ev = {
                "by_platform": { "terms": { "field": "host.os_family", "size": 10 } },
                "by_category": { "terms": { "field": "event_category", "size": 10 } },
                "top_hosts": { "terms": { "field": "host.hostname", "size": 10 } },
                "top_users": { "terms": { "field": "user.name", "size": 10 } }
            }
            res_ev = self.client.search(index=self.index_events, size=0, aggs=aggs_ev)
            buckets_ev = res_ev.get("aggregations", {})
            
            aggs_al = {
                "top_mitre": { "terms": { "field": "mitre_technique", "size": 10 } },
                "by_severity": { "terms": { "field": "severity", "size": 10 } },
                "by_rule": { "terms": { "field": "rule_name", "size": 10 } },
                "daily_timeline": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "day",
                        "format": "yyyy-MM-dd"
                    }
                }
            }
            res_al = self.client.search(index=self.index_alerts, size=0, aggs=aggs_al)
            buckets_al = res_al.get("aggregations", {})
            
            def extract_terms(aggs_data, name):
                return {b["key"]: b["doc_count"] for b in aggs_data.get(name, {}).get("buckets", [])}
                
            return {
                "total_events": count_ev,
                "total_alerts": count_al,
                "events_by_platform": extract_terms(buckets_ev, "by_platform"),
                "events_by_category": extract_terms(buckets_ev, "by_category"),
                "top_hosts": extract_terms(buckets_ev, "top_hosts"),
                "top_users": extract_terms(buckets_ev, "top_users"),
                "top_mitre_techniques": extract_terms(buckets_al, "top_mitre"),
                "alerts_by_severity": extract_terms(buckets_al, "by_severity"),
                "alerts_by_rule": extract_terms(buckets_al, "by_rule"),
                "daily_timeline": {b["key_as_string"]: b["doc_count"] for b in buckets_al.get("daily_timeline", {}).get("buckets", [])}
            }
        except Exception as exc:
            logger.error(f"Elasticsearch statistics aggregation failed: {exc}")
            raise exc

    def health(self) -> Dict[str, Any]:
        """Queries cluster health status details."""
        if not self.is_active or not self.client:
            return {"status": "unavailable", "connected": False, "storage_mode": "json"}
        try:
            cluster_health = self.client.cluster.health()
            info = self.client.info()
            indices_stats = self.client.indices.stats()
            
            return {
                "status": cluster_health.get("status", "unknown"),
                "connected": True,
                "elasticsearch_version": info.get("version", {}).get("number", "unknown"),
                "cluster_name": cluster_health.get("cluster_name"),
                "node_count": cluster_health.get("number_of_nodes"),
                "indices": list(indices_stats.get("indices", {}).keys()),
                "storage_mode": "elasticsearch"
            }
        except Exception as exc:
            logger.error(f"Elasticsearch health details query failed: {exc}")
            return {"status": "error", "connected": False, "error": str(exc), "storage_mode": "json"}

    def close(self) -> None:
        """Closes the current connection client sessions."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
