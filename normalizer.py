# normalizer.py
import re
from datetime import datetime, timezone

AUDIT_MSG_RE = re.compile(r"msg='([^']*)'")
AUDIT_TYPE_RE = re.compile(r"\btype=([A-Z_]+)")
AUDIT_ID_RE   = re.compile(r"audit\(\d+\.\d+:(\d+)\)")

# solo i campi richiesti
NORMALIZED_FIELDS = [
    "timestamp", "source_ip", "signature", "priority", "payload_summary", "detector"
]

def _epoch_to_iso(e):
    try:
        return datetime.fromtimestamp(float(e), tz=timezone.utc).isoformat()
    except Exception:
        return None

def _to_iso(ts):
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return _epoch_to_iso(ts)
    if isinstance(ts, str):
        try:
            if re.fullmatch(r"\d+(\.\d+)?", ts):
                return _epoch_to_iso(ts)
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            return None
    return None

def _detect_kind(rec: dict):
    # AMiner
    if isinstance(rec.get("LogData"), dict) and ("AMiner" in rec or "AnalysisComponent" in rec):
        return "aminer"
    raw = (rec.get("LogData", {}).get("RawLogData") or [None])[0] if isinstance(rec.get("LogData"), dict) else None
    if isinstance(raw, str) and "type=" in raw and " audit(" in raw:
        return "aminer"
    # Wazuh
    if isinstance(rec.get("agent"), dict) or isinstance(rec.get("rule"), dict) or isinstance(rec.get("decoder"), dict):
        return "wazuh"
    if isinstance(rec.get("full_log"), str) and "wazuh" in (rec.get("manager", {}).get("name","")).lower():
        return "wazuh"
    return None

def _parse_aminer(rec: dict):
    ld = rec.get("LogData", {}) or {}
    ts = None
    for k in ("DetectionTimestamp", "Timestamps"):
        arr = ld.get(k) or []
        if arr:
            ts = _to_iso(arr[0]); break

    raw = (ld.get("RawLogData") or [None])[0]
    signature, payload, event_id = None, None, None
    if isinstance(raw, str):
        parts = []
        m = AUDIT_TYPE_RE.search(raw)
        if m: parts.append(m.group(1))
        m = AUDIT_MSG_RE.search(raw)
        if m:
            inner = m.group(1)
            payload = inner
            m2 = re.search(r"\bop=([A-Za-z0-9:_-]+)", inner)
            if m2: parts.append(m2.group(1))
        m = AUDIT_ID_RE.search(raw)
        if m: event_id = m.group(1)
        signature = " ".join(parts) if parts else None
        if event_id:
            signature = f"{signature} (id:{event_id})" if signature else f"id:{event_id}"
    if not payload:
        payload = raw

    return {
        "timestamp": ts,
        "source_ip": (rec.get("AMiner", {}) or {}).get("ID"),
        "signature": signature or (rec.get("AnalysisComponent", {}) or {}).get("AnalysisComponentName"),
        "priority": None,
        "payload_summary": payload,
        "detector": "aminer",
    }

def _parse_wazuh(rec: dict):
    rule = (rec.get("rule", {}) or {})
    ts = _to_iso(rec.get("@timestamp") or (rec.get("predecoder", {}) or {}).get("timestamp"))
    desc = rule.get("description") or (rec.get("decoder", {}) or {}).get("name")
    rid  = rule.get("id")
    signature = f"{desc} (rule:{rid})" if (desc and rid) else (desc or rid)
    return {
        "timestamp": ts,
        "source_ip": (rec.get("agent", {}) or {}).get("ip"),
        "signature": signature,
        "priority": rule.get("level"),
        "payload_summary": rec.get("full_log") or rec.get("location"),
        "detector": "wazuh",
    }

def normalize_records(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        kind = _detect_kind(r)
        if kind == "aminer":
            out.append(_parse_aminer(r))
        elif kind == "wazuh":
            out.append(_parse_wazuh(r))
        else:
            out.append({k: None for k in NORMALIZED_FIELDS})
    return out
