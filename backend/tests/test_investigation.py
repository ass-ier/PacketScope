from test_engine import analyze_capture, fixture
from test_protocols import items


def test_timeline_order_references_and_filters(client):
    capture = analyze_capture(client, fixture.fixtures()["periodic"])
    cid = capture["id"]
    timeline = items(client, cid, "timeline")
    assert [row["timestamp"] for row in timeline] == sorted(row["timestamp"] for row in timeline)
    assert {row["kind"] for row in timeline} >= {"flow", "session", "ioc", "finding"}
    assert all(row["capture_id"] == cid and row["frame_number"] > 0 for row in timeline)
    finding = next(row for row in timeline if row["kind"] == "finding")
    filtered = client.get(f"/api/captures/{cid}/timeline?q=finding_id:{finding['finding_id']}").json()
    assert filtered["total"] == 1
    assert client.get(f"/api/captures/{cid}/timeline?start={fixture.EPOCH+10000}").json()["total"] == 0


def test_graph_edges_have_underlying_flows(client):
    capture = analyze_capture(client, fixture.dns_pair() + fixture.conversation(start=1))
    graph = client.get(f"/api/captures/{capture['id']}/graph").json()
    node_ids = {node["id"] for node in graph["nodes"]}
    assert "10.0.0.10" in node_ids and "domain:fixture.test" in node_ids
    assert all(edge["source"] in node_ids and edge["target"] in node_ids and edge["data"]["flow_ids"] for edge in graph["edges"])
    filtered = client.get(f"/api/captures/{capture['id']}/graph?q=protocol:dns").json()
    assert filtered["shown_flows"] == 1


def test_case_links_notes_and_assessment_persist(client):
    capture = analyze_capture(client, fixture.fixtures()["port-scan"])
    finding = items(client, capture["id"], "findings")[0]
    case = client.post("/api/cases", json={"title":"Synthetic investigation"}).json()
    cid = case["id"]
    linked = client.post(f"/api/cases/{cid}/links", json={"kind":"finding", "entity_id":finding["id"]}).json()
    assert len(linked["captures"]) == 1 and len(linked["findings"]) == 1
    evidence = client.get(f"/api/entities/findings/{finding['id']}").json()["evidence"][0]
    response = client.post(f"/api/cases/{cid}/notes", json={"text":"Synthetic scan observation, no compromise conclusion.",
                                                          "evidence_ids":[evidence["id"]]})
    assert response.status_code == 201
    assert client.post(f"/api/cases/{cid}/notes", json={"text":"invalid", "evidence_ids":["missing"]}).status_code == 422
    client.patch(f"/api/cases/{cid}", json={"status":"Investigating", "verdict":"Suspicious", "confidence":"Medium", "reasoning":"Port pattern; verify authorization."})
    detail = client.get(f"/api/cases/{cid}").json()
    assert detail["case"]["verdict"] == "Suspicious" and detail["case"]["assessed_at"]
    assert detail["notes"][0]["evidence_ids"] == [evidence["id"]]
    assert client.get("/api/search?q=10.0.0.10").json()["results"]
