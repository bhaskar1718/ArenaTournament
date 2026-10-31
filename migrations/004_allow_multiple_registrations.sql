-- Allows one user to create multiple independent registrations for the same tournament.
-- Existing registration rows are retained; no table is dropped or recreated.
ALTER TABLE registrations DROP CONSTRAINT IF EXISTS uq_user_tournament;
