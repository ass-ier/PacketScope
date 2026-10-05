from sqlalchemy import select

from app.models import AttackTechnique, Evidence, Finding, FindingTechnique, Flow
from app.services.query import record

CATALOG = [
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
     "description": "Network service enumeration can be consistent with discovery. Traffic alone does not establish authorization or intent.",
     "url": "https://attack.mitre.org/techniques/T1046/"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
     "description": "Application-layer channels may be used for command and control, but periodic communication alone cannot establish C2.",
     "url": "https://attack.mitre.org/techniques/T1071/"},
]


def seed_attack(db):
    for technique in CATALOG:
        if db.get(AttackTechnique, technique["id"]) is None:
            db.add(AttackTechnique(**technique))
    db.commit()


def map_attack(db, capture):
    for finding in db.scalars(select(Finding).where(Finding.capture_id == capture.id)):
        evidence = list(db.scalars(select(Evidence).where(Evidence.finding_id == finding.id)))
        if not evidence:
            continue
        for technique in finding.rule_snapshot.get("attack_mapping", []):
            if technique == "T1046" and finding.rule_id in ("port-scan", "host-scan"):
                rationale = "Distinct observed TCP connection attempts support a possible service-discovery pattern; authorization and intent are unknown."
                confidence = finding.confidence
            elif technique == "T1071" and finding.rule_id == "beacon":
                flows = list(db.scalars(select(Flow).where(Flow.id.in_([e.flow_id for e in evidence]))))
                if not any(flow.application in ("HTTP", "DNS") and flow.identification == "content" for flow in flows):
                    continue
                rationale = "Observed cleartext application-layer communication and measured periodic connections support a candidate mapping only. Periodicity is not proof of command and control."
                confidence = "Weak indicator"
            else:
                continue
            db.add(FindingTechnique(finding_id=finding.id, technique_id=technique,
                                    confidence=confidence, rationale=rationale))
    db.commit()


def attack_view(db, capture_id):
    rows = db.execute(select(FindingTechnique, AttackTechnique, Finding)
                       .join(AttackTechnique, FindingTechnique.technique_id == AttackTechnique.id)
                       .join(Finding, FindingTechnique.finding_id == Finding.id).where(Finding.capture_id == capture_id))
    mappings = []
    for mapping, technique, finding in rows:
        evidence = list(db.scalars(select(Evidence).where(Evidence.finding_id == finding.id).limit(200)))
        mappings.append({**record(mapping), "technique": record(technique), "source_detection": record(finding),
                         "evidence": [record(e) for e in evidence], "capture_id": capture_id})
    return {"mappings": mappings, "catalog": CATALOG,
            "caveat": "Supported candidate mappings, not a claim of compromise, attribution or complete ATT&CK coverage."}
