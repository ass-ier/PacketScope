from collections import defaultdict

from sqlalchemy import func, select

from app.models import AttackTechnique, DNSQuery, Evidence, Finding, FindingTechnique, Flow, Host, IOC
from app.services.detection import internal
from app.services.query import clauses


def build_graph(db, capture_id, query="", start=None, end=None, topology=False):
    conditions = [Flow.capture_id == capture_id, *clauses(Flow, query, start, end)]
    total = db.scalar(select(func.count()).select_from(Flow).where(*conditions))
    flows = list(db.scalars(select(Flow).where(*conditions).order_by(Flow.start_time, Flow.id).limit(500)))
    flow_ids = {flow.id for flow in flows}
    nodes, edges, groups = {}, {}, defaultdict(int)
    host_map = {host.ip: host for host in db.scalars(select(Host).where(Host.capture_id == capture_id))}

    def node(entity_id, label, kind, collection=None, record_id=None):
        if entity_id not in nodes:
            column = {"internal": 0, "external": 1, "domain": 2, "ioc": 2, "finding": 1, "attack": 2}.get(kind, 1)
            index = groups[column]
            groups[column] += 1
            nodes[entity_id] = {"id": entity_id, "position": {"x": 280 * column, "y": 140 * index},
                                "sourcePosition": "right", "targetPosition": "left",
                                "data": {"label": label, "kind": kind, "collection": collection, "entity_id": record_id},
                                "className": f"graph-{kind}"}

    def edge(source, target, label, flow_id=None):
        key = f"{source}|{target}|{label}"
        if key not in edges:
            edges[key] = {"id": key, "source": source, "target": target, "label": label,
                          "data": {"flow_ids": [], "count": 0}}
        item = edges[key]["data"]
        item["count"] += 1
        if flow_id and flow_id not in item["flow_ids"]:
            item["flow_ids"].append(flow_id)

    for flow in flows:
        for ip in (flow.source_ip, flow.destination_ip):
            host = host_map.get(ip)
            node(ip, ip, "internal" if internal(ip) else "external", "hosts", host.id if host else None)
        edge(flow.source_ip, flow.destination_ip, flow.application, flow.id)
    for dns in db.scalars(select(DNSQuery).where(DNSQuery.flow_id.in_(flow_ids)).limit(200)):
        entity_id = "domain:" + dns.name
        node(entity_id, dns.name, "domain", "dns", dns.id)
        if dns.source_ip in nodes:
            edge(dns.source_ip, entity_id, "queries", dns.flow_id)
    if not topology:
        for ioc, evidence in db.execute(select(IOC, Evidence).join(Evidence, Evidence.ioc_id == IOC.id)
                                        .where(Evidence.flow_id.in_(flow_ids), IOC.type.notin_(["ipv4", "ipv6", "mac", "domain"]))
                                        .limit(100)):
            flow = next((f for f in flows if f.id == evidence.flow_id), None)
            if flow:
                key = "ioc:" + ioc.id
                node(key, f"{ioc.type}: {ioc.value[:70]}", "ioc", "iocs", ioc.id)
                edge(flow.source_ip, key, "observed", flow.id)
        for finding in db.scalars(select(Finding).where(Finding.capture_id == capture_id).limit(100)):
            linked = list(db.scalars(select(Evidence.flow_id).where(Evidence.finding_id == finding.id,
                                                                    Evidence.flow_id.in_(flow_ids)).distinct()))
            if linked and finding.source_ip in nodes:
                key = "finding:" + finding.id
                node(key, finding.title, "finding", "findings", finding.id)
                for flow_id in linked:
                    edge(finding.source_ip, key, "supports", flow_id)
                for mapping in db.scalars(select(FindingTechnique).where(FindingTechnique.finding_id == finding.id)):
                    technique = db.get(AttackTechnique, mapping.technique_id)
                    technique_key = "attack:" + technique.id
                    node(technique_key, f"{technique.id} {technique.name}", "attack", "findings", finding.id)
                    for flow_id in linked:
                        edge(key, technique_key, "candidate", flow_id)
    return {"nodes": list(nodes.values()), "edges": list(edges.values()),
            "total_flows": total, "shown_flows": len(flows), "limited": total > len(flows),
            "limits": "500 flows, 200 DNS observations, 100 IOC links and 100 findings. Filter to focus.",
            "capture_id": capture_id}
