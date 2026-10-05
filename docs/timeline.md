# Timeline and cases

Timeline events index flow starts, observable protocol sessions, first IOC
observations and findings. Each retains capture/frame references plus applicable
flow/session/IOC/finding IDs. Ordering uses packet timestamp and stable row IDs.
Filters support host, protocol, severity, finding ID and UTC epoch time range.

Cases use relational capture/host/IOC/finding links. Attaching a child entity also
attaches its capture. Only completed analyses may be linked. Notes can cite
Evidence IDs; cited evidence must belong to a linked capture. Assessments store
an explicit analyst verdict, confidence, reasoning and assessment timestamp.
No automated rule overwrites the assessment.
