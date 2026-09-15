#!/usr/bin/env python3
"""Flatten the ModSecurity JSON audit log into one flat event per line.

Tails /var/log/modsec/modsec_audit.log, parses each JSON audit transaction, and
appends one flat JSON object per transaction to /var/log/lab/waf_events.jsonl.
Standard library only.

The image writes one JSON object per line (SecAuditLogType Serial + Format
JSON). This still handles multi-line and multiple-objects-per-read defensively
by buffering and decoding incrementally.

Restart-safe and rotation-safe: progress is tracked as (inode, byte offset) in
an offset file, so a restart resumes where it stopped instead of re-emitting.
"""
import json
import os
import re
import sys
import time

AUDIT_LOG = os.getenv("AUDIT_LOG", "/var/log/modsec/modsec_audit.log")
OUT_FILE = os.getenv("OUT_FILE", "/var/log/lab/waf_events.jsonl")
OFFSET_FILE = os.getenv("OFFSET_FILE", "/var/log/lab/.normalizer.offset")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.0"))
# Paranoia level of the current run. Compose passes WAF_PL ("pl3"); we keep the
# digits. It is read from config, not inferred from matched rule tags, because a
# high-paranoia run where only a low-paranoia rule matched would otherwise be
# mislabeled.
_PL_RAW = os.getenv("PARANOIA_LEVEL", "")
PARANOIA_LEVEL = int(re.sub(r"\D", "", _PL_RAW)) if re.search(r"\d", _PL_RAW) else None

# A runaway buffer that never decodes (a genuinely corrupt entry) must not stall
# the tail forever. Past this size we drop to the next newline and move on.
MAX_BUFFER = 5 * 1024 * 1024

SCORE_RE = re.compile(r"Total Score:\s*(\d+)")
# Numeric ModSecurity severities: lower is more severe (0 EMERGENCY .. 7 DEBUG).
SEVERITY_WORD = {
    "EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
    "WARNING": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7,
}


def log(msg):
    print(f"[normalizer] {msg}", file=sys.stderr, flush=True)


def header_ci(headers, name):
    """Case-insensitive header lookup. ModSecurity may preserve the sent case."""
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def severity_rank(details):
    raw = details.get("severity")
    if raw is None:
        return 99
    try:
        return int(raw)
    except (TypeError, ValueError):
        return SEVERITY_WORD.get(str(raw).upper(), 99)


def flatten(obj):
    """Turn one ModSecurity audit transaction into the flat event dict."""
    tx = obj.get("transaction", {}) if isinstance(obj, dict) else {}
    req = tx.get("request", {}) or {}
    resp = tx.get("response", {}) or {}
    messages = tx.get("messages", []) or []

    request_id = header_ci(req.get("headers", {}), "X-Lab-Request-Id") or "none"

    try:
        status = int(resp.get("http_code"))
    except (TypeError, ValueError):
        status = None

    rule_ids = []
    tags = []
    anomaly_score = 0
    has_949 = False
    top = None
    top_rank = 99

    for m in messages:
        details = m.get("details", {}) if isinstance(m, dict) else {}

        rid_raw = details.get("ruleId")
        try:
            rid = int(rid_raw)
            rule_ids.append(rid)
            if 949000 <= rid <= 949999:
                has_949 = True
        except (TypeError, ValueError):
            rid = None

        for t in details.get("tags", []) or []:
            if t not in tags:
                tags.append(t)

        msg_text = m.get("message", "") if isinstance(m, dict) else ""
        # The anomaly score lives in the 949110 "score exceeded" message.
        if "Total Score" in msg_text:
            found = SCORE_RE.search(msg_text)
            if found:
                anomaly_score = int(found.group(1))

        # top_message = the most severe real attack message. The 949110 blocking
        # evaluation is bookkeeping, not the attack, so it never wins if any
        # actual detection message exists.
        is_blocking_eval = rid is not None and 949000 <= rid <= 949999
        if msg_text and not is_blocking_eval:
            rank = severity_rank(details)
            if rank < top_rank:
                top_rank = rank
                top = msg_text
    if top is None and messages:
        top = messages[0].get("message") if isinstance(messages[0], dict) else None

    # blocked per spec: a 403 with a 949xxx blocking rule present.
    blocked = bool(status == 403 and has_949)

    return {
        "ts": tx.get("time_stamp"),
        "request_id": request_id,
        "client_ip": tx.get("client_ip"),
        "method": req.get("method"),
        "uri": req.get("uri"),
        "status": status,
        "blocked": blocked,
        "anomaly_score": anomaly_score,
        "matched_rule_ids": rule_ids,
        "matched_tags": tags,
        "paranoia_level": PARANOIA_LEVEL,
        "top_message": top,
    }


def emit(obj, out):
    event = flatten(obj)
    out.write(json.dumps(event) + "\n")
    out.flush()


def process_buffer(buffer, out):
    """Decode every complete JSON object in buffer; return the remainder."""
    decoder = json.JSONDecoder()
    idx, n = 0, len(buffer)
    while idx < n:
        while idx < n and buffer[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(buffer, idx)
        except json.JSONDecodeError:
            break  # incomplete tail; wait for the rest
        emit(obj, out)
        idx = end
    return buffer[idx:]


def load_offset():
    try:
        with open(OFFSET_FILE) as f:
            data = json.load(f)
        return data.get("inode"), int(data.get("offset", 0))
    except Exception:
        return None, 0


def save_offset(inode, offset):
    tmp = OFFSET_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"inode": inode, "offset": offset}, f)
    os.replace(tmp, OFFSET_FILE)  # atomic on POSIX


def main():
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    inode, offset = load_offset()
    buffer = ""
    log(f"start: audit={AUDIT_LOG} out={OUT_FILE} pl={PARANOIA_LEVEL} "
        f"resume_inode={inode} resume_offset={offset}")

    while True:
        try:
            st = os.stat(AUDIT_LOG)
        except FileNotFoundError:
            time.sleep(POLL_INTERVAL)
            continue

        cur_inode = st.st_ino
        # Rotation: the path now points at a different file. Start it from 0.
        if inode is not None and cur_inode != inode:
            log(f"rotation detected (inode {inode} -> {cur_inode}), restarting at 0")
            offset, buffer = 0, ""
        inode = cur_inode
        # Truncation: file is smaller than where we were. Start over.
        if st.st_size < offset:
            log(f"truncation detected (size {st.st_size} < offset {offset}), restarting at 0")
            offset, buffer = 0, ""

        if st.st_size > offset:
            with open(AUDIT_LOG, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                chunk = f.read()
                offset = f.tell()
            buffer += chunk
            with open(OUT_FILE, "a", encoding="utf-8") as out:
                buffer = process_buffer(buffer, out)
            if len(buffer) > MAX_BUFFER:
                nl = buffer.find("\n")
                log(f"buffer over {MAX_BUFFER} bytes without a valid object; "
                    f"dropping to next newline")
                buffer = buffer[nl + 1:] if nl != -1 else ""
            save_offset(inode, offset)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
