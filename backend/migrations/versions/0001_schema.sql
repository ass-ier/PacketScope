CREATE TABLE attack_techniques (
	id VARCHAR(20) NOT NULL,
	name VARCHAR(180) NOT NULL,
	tactic VARCHAR(80) NOT NULL,
	description TEXT NOT NULL,
	url TEXT NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE captures (
	filename VARCHAR(80) NOT NULL,
	original_filename VARCHAR(200) NOT NULL,
	file_size INTEGER NOT NULL,
	file_type VARCHAR(10) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	packet_count INTEGER NOT NULL,
	start_time FLOAT,
	end_time FLOAT,
	duration FLOAT NOT NULL,
	analysis_status VARCHAR NOT NULL,
	analysis_version VARCHAR(30),
	progress INTEGER NOT NULL,
	stage VARCHAR NOT NULL,
	error TEXT,
	warnings JSON NOT NULL,
	link_types JSON NOT NULL,
	created_at FLOAT NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_captures_analysis_status ON captures (analysis_status);

CREATE INDEX ix_captures_sha256 ON captures (sha256);

CREATE TABLE cases (
	title VARCHAR(200) NOT NULL,
	description TEXT NOT NULL,
	status VARCHAR NOT NULL,
	verdict VARCHAR NOT NULL,
	confidence VARCHAR NOT NULL,
	reasoning TEXT NOT NULL,
	assessed_at FLOAT,
	created_at FLOAT NOT NULL,
	updated_at FLOAT NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id)
);

CREATE INDEX ix_cases_title ON cases (title);

CREATE TABLE detection_rules (
	id VARCHAR(80) NOT NULL,
	name VARCHAR(160) NOT NULL,
	description TEXT NOT NULL,
	severity VARCHAR(30) NOT NULL,
	confidence VARCHAR(40) NOT NULL,
	enabled BOOLEAN NOT NULL,
	config JSON NOT NULL,
	logic TEXT NOT NULL,
	evidence_fields JSON NOT NULL,
	attack_mapping JSON NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE case_captures (
	capture_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (case_id, capture_id),
	FOREIGN KEY(capture_id) REFERENCES captures (id),
	FOREIGN KEY(case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE INDEX ix_case_captures_capture_id ON case_captures (capture_id);

CREATE INDEX ix_case_captures_case_id ON case_captures (case_id);

CREATE TABLE case_notes (
	text TEXT NOT NULL,
	evidence_ids JSON NOT NULL,
	created_at FLOAT NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE INDEX ix_case_notes_case_id ON case_notes (case_id);

CREATE TABLE findings (
	rule_id VARCHAR(80) NOT NULL,
	title VARCHAR(180) NOT NULL,
	description TEXT NOT NULL,
	severity VARCHAR NOT NULL,
	confidence VARCHAR(40) NOT NULL,
	source_ip VARCHAR(50),
	destination_ip VARCHAR(50),
	timestamp FLOAT NOT NULL,
	evidence_count INTEGER NOT NULL,
	statistics JSON NOT NULL,
	rule_snapshot JSON NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(rule_id) REFERENCES detection_rules (id),
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_findings_capture_id ON findings (capture_id);

CREATE INDEX ix_findings_destination_ip ON findings (destination_ip);

CREATE INDEX ix_findings_rule_id ON findings (rule_id);

CREATE INDEX ix_findings_severity ON findings (severity);

CREATE INDEX ix_findings_source_ip ON findings (source_ip);

CREATE TABLE flows (
	source_ip VARCHAR NOT NULL,
	destination_ip VARCHAR NOT NULL,
	source_port INTEGER NOT NULL,
	destination_port INTEGER NOT NULL,
	protocol VARCHAR NOT NULL,
	application VARCHAR NOT NULL,
	identification VARCHAR NOT NULL,
	start_time FLOAT NOT NULL,
	end_time FLOAT NOT NULL,
	duration FLOAT NOT NULL,
	packet_count INTEGER NOT NULL,
	bytes_sent INTEGER NOT NULL,
	bytes_received INTEGER NOT NULL,
	payload_sent INTEGER NOT NULL,
	payload_received INTEGER NOT NULL,
	flags INTEGER NOT NULL,
	state VARCHAR NOT NULL,
	first_frame INTEGER NOT NULL,
	last_frame INTEGER NOT NULL,
	initial_seq INTEGER,
	reconstruction VARCHAR NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_flows_application ON flows (application);

CREATE INDEX ix_flows_capture_id ON flows (capture_id);

CREATE INDEX ix_flows_destination_ip ON flows (destination_ip);

CREATE INDEX ix_flows_destination_port ON flows (destination_port);

CREATE INDEX ix_flows_protocol ON flows (protocol);

CREATE INDEX ix_flows_source_ip ON flows (source_ip);

CREATE TABLE hosts (
	ip VARCHAR NOT NULL,
	mac VARCHAR(40),
	hostname VARCHAR(255),
	first_seen FLOAT NOT NULL,
	last_seen FLOAT NOT NULL,
	protocols JSON NOT NULL,
	ports JSON NOT NULL,
	connections INTEGER NOT NULL,
	bytes_sent INTEGER NOT NULL,
	bytes_received INTEGER NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (capture_id, ip),
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_hosts_capture_id ON hosts (capture_id);

CREATE INDEX ix_hosts_ip ON hosts (ip);

CREATE TABLE iocs (
	type VARCHAR NOT NULL,
	value TEXT NOT NULL,
	first_seen FLOAT NOT NULL,
	last_seen FLOAT NOT NULL,
	source VARCHAR(60) NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (capture_id, type, value),
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_iocs_capture_id ON iocs (capture_id);

CREATE INDEX ix_iocs_type ON iocs (type);

CREATE INDEX ix_iocs_value ON iocs (value);

CREATE TABLE reports (
	capture_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36),
	format VARCHAR(20) NOT NULL,
	filename VARCHAR(100) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	created_at FLOAT NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(capture_id) REFERENCES captures (id),
	FOREIGN KEY(case_id) REFERENCES cases (id)
);

CREATE INDEX ix_reports_capture_id ON reports (capture_id);

CREATE INDEX ix_reports_case_id ON reports (case_id);

CREATE TABLE case_findings (
	finding_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (case_id, finding_id),
	FOREIGN KEY(finding_id) REFERENCES findings (id),
	FOREIGN KEY(case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE INDEX ix_case_findings_case_id ON case_findings (case_id);

CREATE INDEX ix_case_findings_finding_id ON case_findings (finding_id);

CREATE TABLE case_hosts (
	host_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (case_id, host_id),
	FOREIGN KEY(host_id) REFERENCES hosts (id),
	FOREIGN KEY(case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE INDEX ix_case_hosts_case_id ON case_hosts (case_id);

CREATE INDEX ix_case_hosts_host_id ON case_hosts (host_id);

CREATE TABLE case_iocs (
	ioc_id VARCHAR(36) NOT NULL,
	case_id VARCHAR(36) NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (case_id, ioc_id),
	FOREIGN KEY(ioc_id) REFERENCES iocs (id),
	FOREIGN KEY(case_id) REFERENCES cases (id) ON DELETE CASCADE
);

CREATE INDEX ix_case_iocs_case_id ON case_iocs (case_id);

CREATE INDEX ix_case_iocs_ioc_id ON case_iocs (ioc_id);

CREATE TABLE finding_techniques (
	finding_id VARCHAR(36) NOT NULL,
	technique_id VARCHAR(20) NOT NULL,
	confidence VARCHAR(40) NOT NULL,
	rationale TEXT NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(technique_id) REFERENCES attack_techniques (id)
);

CREATE INDEX ix_finding_techniques_finding_id ON finding_techniques (finding_id);

CREATE INDEX ix_finding_techniques_technique_id ON finding_techniques (technique_id);

CREATE TABLE packets (
	frame_number INTEGER NOT NULL,
	timestamp FLOAT NOT NULL,
	"offset" INTEGER NOT NULL,
	captured_length INTEGER NOT NULL,
	length INTEGER NOT NULL,
	link_type INTEGER NOT NULL,
	source_mac VARCHAR(40),
	destination_mac VARCHAR(40),
	source_ip VARCHAR(50),
	destination_ip VARCHAR(50),
	source_port INTEGER,
	destination_port INTEGER,
	protocol VARCHAR NOT NULL,
	transport VARCHAR NOT NULL,
	ip_version INTEGER,
	flags INTEGER NOT NULL,
	payload_length INTEGER NOT NULL,
	flow_id VARCHAR(36),
	metadata_fields JSON NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (capture_id, frame_number),
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_packet_capture_time ON packets (capture_id, timestamp);

CREATE INDEX ix_packets_capture_id ON packets (capture_id);

CREATE INDEX ix_packets_destination_ip ON packets (destination_ip);

CREATE INDEX ix_packets_flow_id ON packets (flow_id);

CREATE INDEX ix_packets_protocol ON packets (protocol);

CREATE INDEX ix_packets_source_ip ON packets (source_ip);

CREATE TABLE sessions (
	flow_id VARCHAR(36) NOT NULL,
	protocol VARCHAR NOT NULL,
	timestamp FLOAT NOT NULL,
	frame_number INTEGER NOT NULL,
	end_frame INTEGER NOT NULL,
	status VARCHAR NOT NULL,
	metadata_fields JSON NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_sessions_capture_id ON sessions (capture_id);

CREATE INDEX ix_sessions_flow_id ON sessions (flow_id);

CREATE INDEX ix_sessions_protocol ON sessions (protocol);

CREATE TABLE threat_intel_results (
	ioc_id VARCHAR(36) NOT NULL,
	provider VARCHAR(80) NOT NULL,
	status VARCHAR(30) NOT NULL,
	result JSON NOT NULL,
	queried_at FLOAT NOT NULL,
	id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(ioc_id) REFERENCES iocs (id) ON DELETE CASCADE
);

CREATE INDEX ix_threat_intel_results_ioc_id ON threat_intel_results (ioc_id);

CREATE TABLE dns_queries (
	session_id VARCHAR(36) NOT NULL,
	flow_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	response_frame INTEGER,
	timestamp FLOAT NOT NULL,
	source_ip VARCHAR NOT NULL,
	server_ip VARCHAR NOT NULL,
	transaction_id INTEGER NOT NULL,
	name VARCHAR NOT NULL,
	query_type VARCHAR(20) NOT NULL,
	response_code INTEGER,
	response_time FLOAT,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(session_id) REFERENCES sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_dns_queries_capture_id ON dns_queries (capture_id);

CREATE INDEX ix_dns_queries_flow_id ON dns_queries (flow_id);

CREATE INDEX ix_dns_queries_name ON dns_queries (name);

CREATE INDEX ix_dns_queries_server_ip ON dns_queries (server_ip);

CREATE INDEX ix_dns_queries_session_id ON dns_queries (session_id);

CREATE INDEX ix_dns_queries_source_ip ON dns_queries (source_ip);

CREATE TABLE evidence (
	packet_id VARCHAR(36),
	frame_number INTEGER NOT NULL,
	timestamp FLOAT NOT NULL,
	flow_id VARCHAR(36),
	session_id VARCHAR(36),
	host_id VARCHAR(36),
	ioc_id VARCHAR(36),
	finding_id VARCHAR(36),
	description TEXT NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(packet_id) REFERENCES packets (id) ON DELETE CASCADE,
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(session_id) REFERENCES sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE CASCADE,
	FOREIGN KEY(ioc_id) REFERENCES iocs (id) ON DELETE CASCADE,
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_evidence_capture_id ON evidence (capture_id);

CREATE INDEX ix_evidence_finding_id ON evidence (finding_id);

CREATE INDEX ix_evidence_flow_id ON evidence (flow_id);

CREATE INDEX ix_evidence_host_id ON evidence (host_id);

CREATE INDEX ix_evidence_ioc_id ON evidence (ioc_id);

CREATE INDEX ix_evidence_packet_id ON evidence (packet_id);

CREATE INDEX ix_evidence_session_id ON evidence (session_id);

CREATE TABLE http_sessions (
	session_id VARCHAR(36) NOT NULL,
	flow_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	response_frame INTEGER,
	timestamp FLOAT NOT NULL,
	source_ip VARCHAR NOT NULL,
	destination_ip VARCHAR NOT NULL,
	method VARCHAR(30),
	host VARCHAR(255),
	uri TEXT,
	status_code INTEGER,
	user_agent TEXT,
	referer TEXT,
	content_type VARCHAR(255),
	request_size INTEGER NOT NULL,
	response_size INTEGER NOT NULL,
	body_sha256 VARCHAR(64),
	body_size INTEGER,
	body_complete BOOLEAN NOT NULL,
	metadata_fields JSON NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(session_id) REFERENCES sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_http_sessions_capture_id ON http_sessions (capture_id);

CREATE INDEX ix_http_sessions_destination_ip ON http_sessions (destination_ip);

CREATE INDEX ix_http_sessions_flow_id ON http_sessions (flow_id);

CREATE INDEX ix_http_sessions_host ON http_sessions (host);

CREATE INDEX ix_http_sessions_session_id ON http_sessions (session_id);

CREATE INDEX ix_http_sessions_source_ip ON http_sessions (source_ip);

CREATE TABLE timeline_events (
	timestamp FLOAT NOT NULL,
	kind VARCHAR NOT NULL,
	summary TEXT NOT NULL,
	protocol VARCHAR NOT NULL,
	host VARCHAR(50),
	frame_number INTEGER NOT NULL,
	flow_id VARCHAR(36),
	session_id VARCHAR(36),
	ioc_id VARCHAR(36),
	finding_id VARCHAR(36),
	severity VARCHAR(30),
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(session_id) REFERENCES sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(ioc_id) REFERENCES iocs (id) ON DELETE CASCADE,
	FOREIGN KEY(finding_id) REFERENCES findings (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_timeline_events_capture_id ON timeline_events (capture_id);

CREATE INDEX ix_timeline_events_finding_id ON timeline_events (finding_id);

CREATE INDEX ix_timeline_events_flow_id ON timeline_events (flow_id);

CREATE INDEX ix_timeline_events_host ON timeline_events (host);

CREATE INDEX ix_timeline_events_kind ON timeline_events (kind);

CREATE INDEX ix_timeline_events_protocol ON timeline_events (protocol);

CREATE INDEX ix_timeline_events_timestamp ON timeline_events (timestamp);

CREATE TABLE tls_sessions (
	session_id VARCHAR(36) NOT NULL,
	flow_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	timestamp FLOAT NOT NULL,
	source_ip VARCHAR NOT NULL,
	destination_ip VARCHAR NOT NULL,
	sni VARCHAR(255),
	version VARCHAR(40),
	cipher_suite VARCHAR(60),
	ja3 VARCHAR(32),
	metadata_fields JSON NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(session_id) REFERENCES sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(flow_id) REFERENCES flows (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_tls_sessions_capture_id ON tls_sessions (capture_id);

CREATE INDEX ix_tls_sessions_destination_ip ON tls_sessions (destination_ip);

CREATE INDEX ix_tls_sessions_flow_id ON tls_sessions (flow_id);

CREATE INDEX ix_tls_sessions_ja3 ON tls_sessions (ja3);

CREATE INDEX ix_tls_sessions_session_id ON tls_sessions (session_id);

CREATE INDEX ix_tls_sessions_sni ON tls_sessions (sni);

CREATE INDEX ix_tls_sessions_source_ip ON tls_sessions (source_ip);

CREATE TABLE certificates (
	tls_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	subject TEXT NOT NULL,
	issuer TEXT NOT NULL,
	serial TEXT NOT NULL,
	valid_from FLOAT NOT NULL,
	valid_until FLOAT NOT NULL,
	signature_algorithm VARCHAR(100) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	sans JSON NOT NULL,
	self_signed BOOLEAN NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(tls_id) REFERENCES tls_sessions (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_certificates_capture_id ON certificates (capture_id);

CREATE INDEX ix_certificates_sha256 ON certificates (sha256);

CREATE INDEX ix_certificates_tls_id ON certificates (tls_id);

CREATE TABLE dns_answers (
	query_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	name VARCHAR NOT NULL,
	type VARCHAR(20) NOT NULL,
	value TEXT NOT NULL,
	ttl INTEGER NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(query_id) REFERENCES dns_queries (id) ON DELETE CASCADE,
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_dns_answers_capture_id ON dns_answers (capture_id);

CREATE INDEX ix_dns_answers_name ON dns_answers (name);

CREATE INDEX ix_dns_answers_query_id ON dns_answers (query_id);

CREATE INDEX ix_dns_answers_value ON dns_answers (value);

CREATE TABLE extracted_files (
	http_id VARCHAR(36) NOT NULL,
	flow_id VARCHAR(36) NOT NULL,
	frame_number INTEGER NOT NULL,
	filename VARCHAR(200) NOT NULL,
	storage_name VARCHAR(80) NOT NULL,
	size INTEGER NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	mime_type VARCHAR(255) NOT NULL,
	source_host VARCHAR(50) NOT NULL,
	destination_host VARCHAR(50) NOT NULL,
	timestamp FLOAT NOT NULL,
	protocol VARCHAR NOT NULL,
	created_at FLOAT NOT NULL,
	id VARCHAR(36) NOT NULL,
	capture_id VARCHAR(36) NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(http_id) REFERENCES http_sessions (id),
	FOREIGN KEY(flow_id) REFERENCES flows (id),
	FOREIGN KEY(capture_id) REFERENCES captures (id) ON DELETE CASCADE
);

CREATE INDEX ix_extracted_files_capture_id ON extracted_files (capture_id);

CREATE UNIQUE INDEX ix_extracted_files_http_id ON extracted_files (http_id);

CREATE INDEX ix_extracted_files_sha256 ON extracted_files (sha256);
