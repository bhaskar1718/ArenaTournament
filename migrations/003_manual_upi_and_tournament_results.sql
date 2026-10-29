-- Run once in the production Neon SQL Editor before deploying the new backend.
ALTER TABLE tournaments ADD COLUMN IF NOT EXISTS room_time VARCHAR(120) NOT NULL DEFAULT '';
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(120) NOT NULL DEFAULT '';
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS kills INTEGER NOT NULL DEFAULT 0;

-- Existing Razorpay payment records are retained for audit/history. New registrations
-- use registrations.status='pending_verification' until the admin verifies the UPI UTR.
