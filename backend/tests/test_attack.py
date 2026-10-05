from test_engine import analyze_capture, fixture


def test_supported_evidence_mappings(client):
    capture = analyze_capture(client, fixture.fixtures()["port-scan"])
    attack = client.get(f"/api/captures/{capture['id']}/attack").json()
    assert len(attack["mappings"]) == 1
    mapping = attack["mappings"][0]
    assert mapping["technique_id"] == "T1046" and mapping["evidence"]
    assert mapping["source_detection"]["rule_id"] == "port-scan"
    capture = analyze_capture(client, fixture.fixtures()["periodic"])
    attack = client.get(f"/api/captures/{capture['id']}/attack").json()
    mapping = next(m for m in attack["mappings"] if m["technique_id"] == "T1071")
    assert mapping["confidence"] == "Weak indicator" and "not proof" in mapping["rationale"]
    graph = client.get(f"/api/captures/{capture['id']}/graph").json()
    assert any(node["id"] == "attack:T1071" for node in graph["nodes"])


def test_no_mappings_without_findings_or_supported_configuration(client):
    capture = analyze_capture(client, fixture.conversation())
    assert not client.get(f"/api/captures/{capture['id']}/attack").json()["mappings"]
    assert client.patch("/api/rules/tls-certificate", json={"attack_mapping":["T1071"]}).status_code == 422
    client.patch("/api/rules/port-scan", json={"attack_mapping":[]})
    capture = analyze_capture(client, fixture.fixtures()["port-scan"])
    assert not client.get(f"/api/captures/{capture['id']}/attack").json()["mappings"]
