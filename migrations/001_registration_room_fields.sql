-- Run once against the existing Neon PostgreSQL database before deploying this version.
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS game_uid VARCHAR(80) NOT NULL DEFAULT '';
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS game_name VARCHAR(120) NOT NULL DEFAULT '';
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS phonepe_number VARCHAR(20) NOT NULL DEFAULT '';
ALTER TABLE tournaments ADD COLUMN IF NOT EXISTS room_id VARCHAR(120) NOT NULL DEFAULT '';
ALTER TABLE tournaments ADD COLUMN IF NOT EXISTS room_password VARCHAR(120) NOT NULL DEFAULT '';
