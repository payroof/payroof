-- Projects, their watch roots, access, and chosen assets.
CREATE TABLE projects (id INTEGER PRIMARY KEY, project TEXT NOT NULL, recovery_public_key BLOB NOT NULL UNIQUE CHECK(length(recovery_public_key)=32), next_address_index INTEGER NOT NULL DEFAULT 0 CHECK(next_address_index BETWEEN 0 AND 2147483648), created_at INTEGER NOT NULL);
CREATE TABLE watch_roots (project_id INTEGER PRIMARY KEY REFERENCES projects(id), root_json TEXT NOT NULL, fingerprint TEXT NOT NULL, root_identity TEXT NOT NULL UNIQUE);
CREATE TABLE access (id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), secret_hash BLOB NOT NULL UNIQUE CHECK(length(secret_hash)=32), name TEXT NOT NULL, permissions_json TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE receive_mappings (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), reference TEXT NOT NULL, address_index INTEGER NOT NULL CHECK(address_index BETWEEN 0 AND 2147483647), address TEXT NOT NULL, allocated_sequence INTEGER NOT NULL, confirmed_sequence INTEGER, created_at INTEGER NOT NULL, UNIQUE(project_id,reference), UNIQUE(project_id,address_index), UNIQUE(project_id,allocated_sequence), UNIQUE(project_id,confirmed_sequence));
CREATE INDEX mapping_address ON receive_mappings(address);

-- Short-lived public flows and abuse controls.
CREATE TABLE pairings (id_hash BLOB PRIMARY KEY, poll_hash BLOB NOT NULL, name TEXT NOT NULL, permissions_json TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','approved','consumed')), project_id INTEGER REFERENCES projects(id), approver TEXT REFERENCES access(id), expires_at INTEGER NOT NULL, last_poll INTEGER NOT NULL DEFAULT 0);
CREATE TABLE recovery_challenges (id_hash BLOB PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), challenge TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE altcha_replay (fingerprint BLOB PRIMARY KEY, purpose TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE rate_limits (identity BLOB NOT NULL, bucket TEXT NOT NULL, window INTEGER NOT NULL, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(identity,bucket,window));
CREATE INDEX rate_limit_expiry ON rate_limits(expires_at);

-- Scanning, transfers, and webhook delivery.
CREATE TABLE chain_state (chain TEXT PRIMARY KEY, next_height INTEGER NOT NULL, healthy INTEGER NOT NULL DEFAULT 0 CHECK(healthy IN (0,1)));
CREATE TABLE chain_blocks (chain TEXT NOT NULL REFERENCES chain_state(chain), height INTEGER NOT NULL, hash TEXT NOT NULL, parent_hash TEXT NOT NULL, PRIMARY KEY(chain,height));
CREATE TABLE transfers (id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), mapping_id INTEGER NOT NULL REFERENCES receive_mappings(id), chain TEXT NOT NULL, asset TEXT NOT NULL, address TEXT NOT NULL, transaction_id TEXT NOT NULL, event_index INTEGER NOT NULL, amount TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('seen','confirmed','orphaned')), block_height INTEGER NOT NULL, block_hash TEXT NOT NULL, UNIQUE(project_id,chain,transaction_id,event_index,asset,address));
CREATE TABLE transfer_events (id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL REFERENCES transfers(id), event TEXT NOT NULL CHECK(event IN ('seen','confirmed')), payload_json TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(transfer_id,event));
CREATE TABLE webhooks (id TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), url TEXT NOT NULL, events_json TEXT NOT NULL, secret_ciphertext TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE webhook_deliveries (webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE, event_id TEXT NOT NULL REFERENCES transfer_events(id), attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, sent_at INTEGER, failed_at INTEGER, last_status INTEGER, PRIMARY KEY(webhook_id,event_id));
CREATE TABLE worker_state (name TEXT PRIMARY KEY, healthy INTEGER NOT NULL CHECK(healthy IN (0,1)), heartbeat INTEGER NOT NULL);

CREATE TRIGGER immutable_project BEFORE UPDATE OF project,recovery_public_key ON projects BEGIN SELECT RAISE(ABORT,'immutable_project'); END;
CREATE TRIGGER immutable_permissions BEFORE UPDATE OF permissions_json,project_id,secret_hash ON access BEGIN SELECT RAISE(ABORT,'immutable_access'); END;
CREATE TRIGGER immutable_mapping BEFORE UPDATE OF project_id,reference,address_index,address,allocated_sequence ON receive_mappings BEGIN SELECT RAISE(ABORT,'immutable_mapping'); END;
