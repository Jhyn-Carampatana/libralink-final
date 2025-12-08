-- Add author_name and publisher_name columns to books table
-- This simplifies the schema by storing author/publisher as text instead of relations

ALTER TABLE books ADD COLUMN IF NOT EXISTS author_name TEXT;
ALTER TABLE books ADD COLUMN IF NOT EXISTS publisher_name TEXT;
ALTER TABLE books ADD COLUMN IF NOT EXISTS category_id UUID REFERENCES categories(id);

-- Migrate existing data from relational tables to new columns
UPDATE books b SET 
  author_name = (
    SELECT string_agg(a.name, ', ') 
    FROM book_authors ba 
    JOIN authors a ON ba.author_id = a.id 
    WHERE ba.book_id = b.id
  ),
  publisher_name = (
    SELECT p.name FROM publishers p WHERE p.id = b.publisher_id
  ),
  category_id = (
    SELECT bc.category_id FROM book_categories bc WHERE bc.book_id = b.id LIMIT 1
  );

-- Set defaults for any null values
UPDATE books SET author_name = 'Unknown Author' WHERE author_name IS NULL;
UPDATE books SET publisher_name = '' WHERE publisher_name IS NULL;
