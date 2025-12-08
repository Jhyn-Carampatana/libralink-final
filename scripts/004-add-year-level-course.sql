-- Add year_level and course columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS year_level VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS course VARCHAR(255);

-- Remove the check constraint on books table that prevents available_copies > total_copies
ALTER TABLE books DROP CONSTRAINT IF EXISTS valid_copies;
