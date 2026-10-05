# Supported ATT&CK candidates

PacketScope includes a deliberately small, offline reference catalog:

* T1046 Network Service Discovery (Discovery): supported by port/host scan
  findings with actual distinct destination evidence.
* T1071 Application Layer Protocol (Command and Control): a **weak candidate**
  only when periodic bidirectional flows also contain confirmed HTTP/DNS content.
  Periodicity alone never proves C2; encrypted/unknown application traffic is
  insufficient for this mapping.

Technique names and reference URLs are a static project catalog, not a promise
of tracking every ATT&CK release. Mapping definitions can be disabled through the
rule configuration. Unsupported rule/technique combinations are rejected.
Findings retain their mapping configuration snapshot.

Each FindingTechnique row references a finding; its Evidence rows supply
capture/frame/flow support. Visualization and graph edges show rationale,
confidence and underlying findings. No mapping is created without evidence.
No inference of compromise, actor attribution, exfiltration or lateral movement
is made from protocol names alone.
