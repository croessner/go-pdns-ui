-- PowerDNS Authoritative PostgreSQL schema
-- Source adapted from official PowerDNS PostgreSQL backend schema.

CREATE TABLE IF NOT EXISTS domains (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INTEGER DEFAULT NULL,
  type                  VARCHAR(8) NOT NULL,
  notified_serial       BIGINT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  options               TEXT DEFAULT NULL,
  catalog               VARCHAR(255) DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS name_index ON domains(name);
CREATE INDEX IF NOT EXISTS catalog_idx ON domains(catalog);

CREATE TABLE IF NOT EXISTS records (
  id                    BIGSERIAL PRIMARY KEY,
  domain_id             INTEGER DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               TEXT DEFAULT NULL,
  ttl                   INTEGER DEFAULT NULL,
  prio                  INTEGER DEFAULT NULL,
  disabled              BOOLEAN DEFAULT FALSE,
  ordername             VARCHAR(255),
  auth                  BOOLEAN DEFAULT TRUE,
  CONSTRAINT domain_exists
    FOREIGN KEY(domain_id) REFERENCES domains(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS rec_name_index ON records(name);
CREATE INDEX IF NOT EXISTS nametype_index ON records(name, type);
CREATE INDEX IF NOT EXISTS domain_id_idx ON records(domain_id);
CREATE INDEX IF NOT EXISTS recordorder ON records(domain_id, ordername text_pattern_ops);
CREATE INDEX IF NOT EXISTS auth_idx ON records(auth);

CREATE TABLE IF NOT EXISTS supermasters (
  ip                    INET NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) NOT NULL,
  PRIMARY KEY(ip, nameserver)
);

CREATE TABLE IF NOT EXISTS comments (
  id                    SERIAL PRIMARY KEY,
  domain_id             INTEGER NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INTEGER NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               TEXT NOT NULL,
  CONSTRAINT comments_domain_id_fkey
    FOREIGN KEY(domain_id) REFERENCES domains(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS comments_domain_id_idx ON comments(domain_id);
CREATE INDEX IF NOT EXISTS comments_name_type_idx ON comments(name, type);
CREATE INDEX IF NOT EXISTS comments_order_idx ON comments(domain_id, modified_at);

CREATE TABLE IF NOT EXISTS domainmetadata (
  id                    SERIAL PRIMARY KEY,
  domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);

CREATE INDEX IF NOT EXISTS domainmetadata_idx ON domainmetadata(domain_id, kind);

CREATE TABLE IF NOT EXISTS cryptokeys (
  id                    SERIAL PRIMARY KEY,
  domain_id             INTEGER REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INTEGER NOT NULL,
  active                BOOLEAN,
  published             BOOLEAN DEFAULT TRUE,
  content               TEXT
);

CREATE INDEX IF NOT EXISTS domainidindex ON cryptokeys(domain_id);

CREATE TABLE IF NOT EXISTS tsigkeys (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255)
);

CREATE UNIQUE INDEX IF NOT EXISTS namealgoindex ON tsigkeys(name, algorithm);
