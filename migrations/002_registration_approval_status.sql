-- Run once in the Neon SQL Editor against the production database.
ALTER TABLE registrations
ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'pending';

-- Existing registrations are intentionally left pending approval.
-- Payment status remains in the existing `status` column and is not changed.
