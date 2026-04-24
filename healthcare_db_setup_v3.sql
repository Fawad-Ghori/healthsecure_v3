-- =============================================================================
--  HEALTHSECURE DATABASE — SETUP SCRIPT v3.0
--  Demonstrates: RBAC, Audit Logging, Record Integrity, Edit Tracking
--
--  Run:  mysql -u root -p < healthcare_db_setup_v3.sql
--        OR paste into MySQL Workbench and Execute All
-- =============================================================================

DROP DATABASE IF EXISTS healthcare_db;
CREATE DATABASE healthcare_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE healthcare_db;


-- =============================================================================
--  TABLE: users
--
--  REGULATORY RELEVANCE — HIPAA §164.312(a)(1) — Access Control
--  Every system user is assigned a `role`. The application reads this at
--  login and enforces different permission levels throughout the session.
--  Storing bcrypt hashes (not plain text) satisfies HIPAA's requirement
--  for "appropriate technical safeguards" protecting ePHI access.
-- =============================================================================
CREATE TABLE users (
    id            INT          NOT NULL AUTO_INCREMENT,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('Admin','Staff') NOT NULL DEFAULT 'Staff',
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);


-- =============================================================================
--  TABLE: patients
--
--  REGULATORY RELEVANCE — HIPAA §164.312(c)(1) — Integrity Controls
--  `created_by` / `created_at` and `updated_by` / `updated_at` create a
--  two-layer attribution trail:
--    • Who originally entered the record and when.
--    • Who last modified the record and when.
--  This supports breach investigations: investigators can always reconstruct
--  what the record looked like before any modification.
--  is_deleted implements "soft delete" — the record is flagged hidden rather
--  than physically removed, preserving the data trail as required by many
--  healthcare retention policies (HIPAA requires 6-year retention).
-- =============================================================================
CREATE TABLE patients (
    id                INT          NOT NULL AUTO_INCREMENT,
    name              VARCHAR(120) NOT NULL,
    age               TINYINT      NOT NULL CHECK (age > 0 AND age <= 150),
    gender            ENUM('Male','Female','Other') NOT NULL,
    medical_condition VARCHAR(255) NOT NULL,

    -- Record integrity: creation attribution
    created_by        VARCHAR(50)  NOT NULL,
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Record integrity: last-edit attribution
    updated_by        VARCHAR(50)  NULL,
    updated_at        TIMESTAMP    NULL ON UPDATE CURRENT_TIMESTAMP,

    -- Soft delete: HIPAA requires 6-year data retention; hard deletes
    -- would destroy the audit trail. We flag records as deleted instead.
    is_deleted        TINYINT(1)   NOT NULL DEFAULT 0,
    deleted_by        VARCHAR(50)  NULL,
    deleted_at        TIMESTAMP    NULL,

    PRIMARY KEY (id)
);


-- =============================================================================
--  TABLE: audit_logs
--
--  REGULATORY RELEVANCE — HIPAA §164.312(b) — Audit Controls
--  This table is the system's immutable event ledger. Every meaningful action
--  (logins, logouts, patient adds/edits/deletes, access-denied events) is
--  recorded with a timestamp, username, action description, and outcome.
--
--  MAINTENANCE IMPLICATION: Regulations require this table to be reviewed
--  regularly. The application exposes it only to Admins, and includes filters
--  so compliance officers can quickly locate suspicious activity patterns.
--
--  In production: the DB user the app connects with should have INSERT-only
--  privileges on this table — no UPDATE or DELETE — making logs tamper-proof.
-- =============================================================================
CREATE TABLE audit_logs (
    id         INT          NOT NULL AUTO_INCREMENT,
    timestamp  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username   VARCHAR(50)  NOT NULL,
    action     VARCHAR(512) NOT NULL,
    outcome    ENUM('SUCCESS','FAILURE','INFO','WARNING') NOT NULL DEFAULT 'INFO',
    ip_address VARCHAR(45)  NULL,   -- Records client IP for geo-anomaly detection
    PRIMARY KEY (id)
);


-- =============================================================================
--  SEED DATA — Users
--
--  Admin:  username=admin   password=admin123
--  Staff:  username=staff1  password=staff123
--
--  Hashes generated with Python:
--    import bcrypt; bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
-- =============================================================================
INSERT INTO users (username, password_hash, role) VALUES
(
    'admin',
    '$2b$12$tPMHI6hMvdmKHoKy45qX4OqsBFNRRWiHFQJfPqCUbxCp7U0Fivq4a',
    'Admin'
),
(
    'staff1',
    '$2b$12$ELQ4RKvVVkPnVz.cXJkRieVK4VCfvF4VzSHCOvqmh9TcBJOHmgFqm',
    'Staff'
);


-- =============================================================================
--  SEED DATA — Patients
-- =============================================================================
INSERT INTO patients (name, age, gender, medical_condition, created_by) VALUES
    ('Ayesha Khan',    34, 'Female', 'Hypertension',       'admin'),
    ('Omar Farooq',    52, 'Male',   'Type 2 Diabetes',    'admin'),
    ('Sara Malik',     28, 'Female', 'Asthma',             'staff1'),
    ('Bilal Ahmed',    45, 'Male',   'Chronic Back Pain',  'admin'),
    ('Nadia Hussain',  61, 'Female', 'Arthritis',          'staff1'),
    ('Kamran Iqbal',   39, 'Male',   'Hypertension',       'admin'),
    ('Zara Sheikh',    22, 'Female', 'Migraine',           'staff1');


-- =============================================================================
--  SEED DATA — Initial Audit Entry
-- =============================================================================
INSERT INTO audit_logs (username, action, outcome) VALUES
    ('system', 'Database v3 initialised. Schema and seed data loaded.', 'INFO');


-- Confirmation
SELECT 'Setup complete.' AS status;
SELECT 'Users:' AS ''; SELECT id, username, role FROM users;
SELECT 'Patients:' AS ''; SELECT id, name, created_by FROM patients;
