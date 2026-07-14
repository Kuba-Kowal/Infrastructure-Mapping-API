CREATE DATABASE graph;

USE graph;

CREATE TABLE nodes(
    node_hash VARCHAR(64) PRIMARY KEY,
    type ENUM('FQDN', 'IP', 'ASN', 'CERT', 'ORG', 'PREFIX', 'DNS') NOT NULL,
    data VARCHAR(255) NOT NULL,
    properties JSON
);

CREATE TABLE relationships(
    relationship_id INT PRIMARY KEY AUTO_INCREMENT,
    source_hash varchar(64) NOT NULL,
    target_hash varchar(64) NOT NULL,

    FOREIGN KEY (source_hash) REFERENCES nodes(node_hash),
    FOREIGN KEY (target_hash) REFERENCES nodes(node_hash),

    relationship_type ENUM('cert_to_fqdn', 'fqdn_to_dns', 'fqdn_to_pdns', 'ip_to_prefix', 'prefix_to_asn', 'asn_to_org') NOT NULL,

    CONSTRAINT unique_relationship_pair UNIQUE (source_hash, target_hash, relationship_type),

    observed_at VARCHAR(255) NOT NULL
);

CREATE TABLE scans(
    scan_id INT PRIMARY KEY AUTO_INCREMENT,
    apex_domain VARCHAR(255) NOT NULL,
    query_domain VARCHAR(255) NOT NULL,
    started_at DATETIME,
    finished_at DATETIME,
    status ENUM('QUEUED', 'PROCESSING', 'COMPLETE', 'FAILED')
);

CREATE TABLE scan_relationships(
    relationship_id INT NOT NULL,
    scan_id INT NOT NULL,

    FOREIGN KEY (relationship_id) REFERENCES relationships(relationship_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),

    CONSTRAINT unique_scan_relationship UNIQUE (relationship_id, scan_id)
);
