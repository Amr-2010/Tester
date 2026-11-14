CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','manager','operator','viewer')),created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS clients(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,contact TEXT DEFAULT '',email TEXT DEFAULT '',phone TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS channels(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL UNIQUE,category TEXT DEFAULT '',frequency TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS programs(id BIGSERIAL PRIMARY KEY,channel_id BIGINT REFERENCES channels(id) ON DELETE SET NULL,name TEXT NOT NULL,air_time TIME,description TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS campaigns(id BIGSERIAL PRIMARY KEY,client_id BIGINT REFERENCES clients(id) ON DELETE SET NULL,name TEXT NOT NULL,start_date DATE,end_date DATE,budget NUMERIC(14,2) DEFAULT 0,status TEXT DEFAULT 'planned' CHECK(status IN ('planned','active','paused','completed')),created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS creatives(id BIGSERIAL PRIMARY KEY,campaign_id BIGINT REFERENCES campaigns(id) ON DELETE CASCADE,name TEXT NOT NULL,duration_seconds INT DEFAULT 30 CHECK(duration_seconds>0),reference_url TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS spots(id BIGSERIAL PRIMARY KEY,campaign_id BIGINT REFERENCES campaigns(id) ON DELETE CASCADE,channel_id BIGINT REFERENCES channels(id) ON DELETE SET NULL,program_id BIGINT REFERENCES programs(id) ON DELETE SET NULL,creative_id BIGINT REFERENCES creatives(id) ON DELETE SET NULL,planned_at TIMESTAMPTZ NOT NULL,price NUMERIC(14,2) DEFAULT 0,created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS airings(id BIGSERIAL PRIMARY KEY,spot_id BIGINT REFERENCES spots(id) ON DELETE CASCADE,actual_at TIMESTAMPTZ NOT NULL,source TEXT DEFAULT 'manual',evidence_url TEXT DEFAULT '',notes TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_spots_planned ON spots(planned_at);
CREATE INDEX IF NOT EXISTS idx_airings_spot ON airings(spot_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
CREATE TABLE IF NOT EXISTS test_runs(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,target_type TEXT NOT NULL CHECK(target_type IN ('website','api','windows_exe','android_apk','advertising_media','broadcast_monitor')),target_url TEXT DEFAULT '',notes TEXT DEFAULT '',created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS test_results(id BIGSERIAL PRIMARY KEY,run_id BIGINT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,test_name TEXT NOT NULL,result TEXT NOT NULL CHECK(result IN ('passed','failed','blocked')),details TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_test_results_run ON test_results(run_id);

-- Additive migration: never drops existing customer data.
ALTER TABLE users ADD COLUMN IF NOT EXISTS client_id BIGINT REFERENCES clients(id) ON DELETE RESTRICT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS client_id BIGINT REFERENCES clients(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_users_client ON users(client_id);
CREATE INDEX IF NOT EXISTS idx_runs_client ON test_runs(client_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_client ON campaigns(client_id);
-- Existing test runs are intentionally NOT exposed to clients until assigned.

-- Expand existing test-run type constraint without deleting records.
ALTER TABLE test_runs DROP CONSTRAINT IF EXISTS test_runs_target_type_check;
ALTER TABLE test_runs ADD CONSTRAINT test_runs_target_type_check CHECK (target_type IN ('website','api','windows_exe','android_apk','advertising_media','broadcast_monitor'));
