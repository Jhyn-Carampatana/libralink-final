-- LibraLink Seed Data
-- This script populates the database with initial data

-- =====================
-- SEED CATEGORIES
-- =====================

INSERT INTO categories (id, name, description) VALUES
  ('c1000000-0000-0000-0000-000000000001', 'Thriller', 'Suspenseful and exciting stories'),
  ('c1000000-0000-0000-0000-000000000002', 'Mystery', 'Crime and detective stories'),
  ('c1000000-0000-0000-0000-000000000003', 'Horror', 'Scary and frightening stories'),
  ('c1000000-0000-0000-0000-000000000004', 'Psychological Thriller', 'Mind-bending suspense'),
  ('c1000000-0000-0000-0000-000000000005', 'Science Fiction', 'Futuristic and technological stories'),
  ('c1000000-0000-0000-0000-000000000006', 'Fantasy', 'Magical and otherworldly stories'),
  ('c1000000-0000-0000-0000-000000000007', 'Romance', 'Love stories'),
  ('c1000000-0000-0000-0000-000000000008', 'Non-Fiction', 'Factual and educational'),
  ('c1000000-0000-0000-0000-000000000009', 'Biography', 'Life stories of real people'),
  ('c1000000-0000-0000-0000-000000000010', 'Educational', 'Learning and reference materials');

-- =====================
-- SEED AUTHORS
-- =====================

INSERT INTO authors (id, name, bio) VALUES
  ('a1000000-0000-0000-0000-000000000001', 'Dan Brown', 'American author best known for his thriller novels'),
  ('a1000000-0000-0000-0000-000000000002', 'Alex Michaelides', 'British-Cypriot author and screenwriter'),
  ('a1000000-0000-0000-0000-000000000003', 'Stephen King', 'American author of horror, supernatural fiction'),
  ('a1000000-0000-0000-0000-000000000004', 'Jessica Barry', 'Bestselling thriller author'),
  ('a1000000-0000-0000-0000-000000000005', 'Gillian Flynn', 'American author known for psychological thrillers'),
  ('a1000000-0000-0000-0000-000000000006', 'Paula Hawkins', 'British author of The Girl on the Train');

-- =====================
-- SEED PUBLISHERS
-- =====================

INSERT INTO publishers (id, name, website) VALUES
  ('p1000000-0000-0000-0000-000000000001', 'Doubleday', 'https://doubleday.com'),
  ('p1000000-0000-0000-0000-000000000002', 'Celadon Books', 'https://celadonbooks.com'),
  ('p1000000-0000-0000-0000-000000000003', 'Scribner', 'https://scribner.com'),
  ('p1000000-0000-0000-0000-000000000004', 'Crown Publishing', 'https://crownpublishing.com'),
  ('p1000000-0000-0000-0000-000000000005', 'Penguin Random House', 'https://penguinrandomhouse.com');

-- =====================
-- SEED BOOKS
-- =====================

INSERT INTO books (id, title, isbn, description, cover_url, publisher_id, publication_year, total_copies, available_copies, rating, rating_count, status) VALUES
  ('b1000000-0000-0000-0000-000000000001', 'Origin', '978-0385514231', 'Origin is a 2017 mystery-thriller novel by American author Dan Brown. It is the fifth installment in the Robert Langdon series, following previous bestsellers such as The Da Vinci Code and Angels & Demons.', '/origin-dan-brown-book-cover.jpg', 'p1000000-0000-0000-0000-000000000001', 2017, 100, 42, 4.5, 1250, 'available'),
  ('b1000000-0000-0000-0000-000000000002', 'The Fury', '978-1250758989', 'A thrilling psychological mystery about revenge and redemption set on a private Greek island.', '/the-fury-alex-michaelides-book-cover-blue-eye.jpg', 'p1000000-0000-0000-0000-000000000002', 2024, 50, 35, 4.3, 890, 'available'),
  ('b1000000-0000-0000-0000-000000000003', 'The Maidens', '978-1250326041', 'A psychological thriller about a group therapy patient who becomes obsessed with a Greek tragedy professor.', '/the-maidens-book-cover-dark-sculpture.jpg', 'p1000000-0000-0000-0000-000000000002', 2021, 75, 50, 4.2, 1100, 'available'),
  ('b1000000-0000-0000-0000-000000000004', 'Gerald''s Game', '978-1501143847', 'A woman accidentally kills her husband during a bondage game and must survive alone, handcuffed to a bed.', '/geralds-game-stephen-king-book-cover-red-horror.jpg', 'p1000000-0000-0000-0000-000000000003', 1992, 60, 45, 4.0, 980, 'available'),
  ('b1000000-0000-0000-0000-000000000005', 'Don''t Turn Around', '978-0063069763', 'A heart-pounding thriller about two women on a road trip who realize they''re being followed.', '/dont-turn-around-thriller-book-cover-teal.jpg', 'p1000000-0000-0000-0000-000000000004', 2020, 40, 28, 4.1, 650, 'available'),
  ('b1000000-0000-0000-0000-000000000006', 'Amazing Facts', '978-1234567890', 'A collection of incredible facts and stories that will amaze and educate readers of all ages.', '/amazing-facts-book-cover-colorful-educational.jpg', 'p1000000-0000-0000-0000-000000000005', 2023, 80, 70, 4.6, 420, 'available'),
  ('b1000000-0000-0000-0000-000000000007', 'Gone Girl', '978-0307588371', 'A thriller about a man who becomes the prime suspect when his wife goes missing on their anniversary.', '/gone-girl-book-cover.jpg', 'p1000000-0000-0000-0000-000000000004', 2012, 90, 55, 4.7, 2100, 'available'),
  ('b1000000-0000-0000-0000-000000000008', 'The Girl on the Train', '978-1594634024', 'A psychological thriller about a woman who becomes entangled in a missing persons investigation.', '/placeholder.svg?height=400&width=280', 'p1000000-0000-0000-0000-000000000005', 2015, 85, 60, 4.4, 1800, 'available');

-- =====================
-- SEED BOOK_AUTHORS
-- =====================

INSERT INTO book_authors (book_id, author_id) VALUES
  ('b1000000-0000-0000-0000-000000000001', 'a1000000-0000-0000-0000-000000000001'),
  ('b1000000-0000-0000-0000-000000000002', 'a1000000-0000-0000-0000-000000000002'),
  ('b1000000-0000-0000-0000-000000000003', 'a1000000-0000-0000-0000-000000000002'),
  ('b1000000-0000-0000-0000-000000000004', 'a1000000-0000-0000-0000-000000000003'),
  ('b1000000-0000-0000-0000-000000000005', 'a1000000-0000-0000-0000-000000000004'),
  ('b1000000-0000-0000-0000-000000000007', 'a1000000-0000-0000-0000-000000000005'),
  ('b1000000-0000-0000-0000-000000000008', 'a1000000-0000-0000-0000-000000000006');

-- =====================
-- SEED BOOK_CATEGORIES
-- =====================

INSERT INTO book_categories (book_id, category_id) VALUES
  ('b1000000-0000-0000-0000-000000000001', 'c1000000-0000-0000-0000-000000000001'),
  ('b1000000-0000-0000-0000-000000000001', 'c1000000-0000-0000-0000-000000000002'),
  ('b1000000-0000-0000-0000-000000000002', 'c1000000-0000-0000-0000-000000000004'),
  ('b1000000-0000-0000-0000-000000000003', 'c1000000-0000-0000-0000-000000000004'),
  ('b1000000-0000-0000-0000-000000000004', 'c1000000-0000-0000-0000-000000000003'),
  ('b1000000-0000-0000-0000-000000000005', 'c1000000-0000-0000-0000-000000000001'),
  ('b1000000-0000-0000-0000-000000000006', 'c1000000-0000-0000-0000-000000000010'),
  ('b1000000-0000-0000-0000-000000000007', 'c1000000-0000-0000-0000-000000000004'),
  ('b1000000-0000-0000-0000-000000000008', 'c1000000-0000-0000-0000-000000000004');

-- =====================
-- SEED USERS (password is 'password123' hashed with bcrypt)
-- =====================

INSERT INTO users (id, email, password_hash, full_name, role, status, university_id, university_name, department, avatar_url) VALUES
  ('u1000000-0000-0000-0000-000000000001', 'admin@libralink.com', '$2b$10$rQZ8K.v0vMkXzjqX7bMrXOQhQHVz1LlmqPwNz5z1z1z1z1z1z1z1u', 'System Administrator', 'admin', 'active', 'ADM001', 'LibraLink University', 'Administration', '/admin-avatar.jpg'),
  ('u1000000-0000-0000-0000-000000000002', 'librarian@libralink.com', '$2b$10$rQZ8K.v0vMkXzjqX7bMrXOQhQHVz1LlmqPwNz5z1z1z1z1z1z1z1u', 'Sarah Mitchell', 'librarian', 'active', 'LIB001', 'LibraLink University', 'Library Services', '/librarian-portrait.jpg'),
  ('u1000000-0000-0000-0000-000000000003', 'asla.heimdall@webdevmastery.com', '$2b$10$rQZ8K.v0vMkXzjqX7bMrXOQhQHVz1LlmqPwNz5z1z1z1z1z1z1z1u', 'Asla Heimdall', 'student', 'active', '234567856', 'WebDev Mastery University', 'Web Development', '/student-portrait-photo.jpg'),
  ('u1000000-0000-0000-0000-000000000004', 'john.smith@university.edu', '$2b$10$rQZ8K.v0vMkXzjqX7bMrXOQhQHVz1LlmqPwNz5z1z1z1z1z1z1z1u', 'John Smith', 'student', 'active', '98765432', 'WebDev Mastery University', 'Computer Science', NULL),
  ('u1000000-0000-0000-0000-000000000005', 'jane.doe@university.edu', '$2b$10$rQZ8K.v0vMkXzjqX7bMrXOQhQHVz1LlmqPwNz5z1z1z1z1z1z1z1u', 'Jane Doe', 'faculty', 'active', 'FAC001', 'WebDev Mastery University', 'Literature', NULL);

-- =====================
-- SEED BORROW REQUESTS
-- =====================

INSERT INTO borrow_requests (id, user_id, book_id, status, requested_at, approved_at, approved_by, due_date, returned_at) VALUES
  ('br100000-0000-0000-0000-000000000001', 'u1000000-0000-0000-0000-000000000003', 'b1000000-0000-0000-0000-000000000001', 'approved', NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 'u1000000-0000-0000-0000-000000000002', CURRENT_DATE + INTERVAL '4 days', NULL),
  ('br100000-0000-0000-0000-000000000002', 'u1000000-0000-0000-0000-000000000003', 'b1000000-0000-0000-0000-000000000002', 'approved', NOW() - INTERVAL '20 days', NOW() - INTERVAL '19 days', 'u1000000-0000-0000-0000-000000000002', CURRENT_DATE - INTERVAL '5 days', NULL),
  ('br100000-0000-0000-0000-000000000003', 'u1000000-0000-0000-0000-000000000004', 'b1000000-0000-0000-0000-000000000003', 'pending', NOW() - INTERVAL '1 day', NULL, NULL, NULL, NULL),
  ('br100000-0000-0000-0000-000000000004', 'u1000000-0000-0000-0000-000000000004', 'b1000000-0000-0000-0000-000000000004', 'approved', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', 'u1000000-0000-0000-0000-000000000002', CURRENT_DATE + INTERVAL '9 days', NULL),
  ('br100000-0000-0000-0000-000000000005', 'u1000000-0000-0000-0000-000000000005', 'b1000000-0000-0000-0000-000000000007', 'returned', NOW() - INTERVAL '30 days', NOW() - INTERVAL '29 days', 'u1000000-0000-0000-0000-000000000002', NOW() - INTERVAL '15 days', NOW() - INTERVAL '16 days');

-- =====================
-- SEED RESERVATIONS
-- =====================

INSERT INTO reservations (id, user_id, book_id, status, reserved_at, expires_at) VALUES
  ('r1000000-0000-0000-0000-000000000001', 'u1000000-0000-0000-0000-000000000004', 'b1000000-0000-0000-0000-000000000001', 'active', NOW() - INTERVAL '2 days', NOW() + INTERVAL '5 days'),
  ('r1000000-0000-0000-0000-000000000002', 'u1000000-0000-0000-0000-000000000005', 'b1000000-0000-0000-0000-000000000002', 'active', NOW() - INTERVAL '1 day', NOW() + INTERVAL '6 days');

-- =====================
-- SEED FINES
-- =====================

INSERT INTO fines (id, user_id, borrow_request_id, book_id, amount, reason, status, description, created_by) VALUES
  ('f1000000-0000-0000-0000-000000000001', 'u1000000-0000-0000-0000-000000000003', 'br100000-0000-0000-0000-000000000002', 'b1000000-0000-0000-0000-000000000002', 2.50, 'overdue', 'unpaid', 'Book returned 5 days late', 'u1000000-0000-0000-0000-000000000002');

-- =====================
-- SEED SYSTEM LOGS
-- =====================

INSERT INTO system_logs (user_id, action, entity_type, entity_id, details, ip_address) VALUES
  ('u1000000-0000-0000-0000-000000000001', 'user_login', 'user', 'u1000000-0000-0000-0000-000000000001', '{"method": "password"}', '192.168.1.1'),
  ('u1000000-0000-0000-0000-000000000002', 'book_borrowed', 'borrow_request', 'br100000-0000-0000-0000-000000000001', '{"book": "Origin", "user": "Asla Heimdall"}', '192.168.1.2'),
  ('u1000000-0000-0000-0000-000000000002', 'fine_created', 'fine', 'f1000000-0000-0000-0000-000000000001', '{"amount": 2.50, "reason": "overdue"}', '192.168.1.2'),
  ('u1000000-0000-0000-0000-000000000003', 'user_login', 'user', 'u1000000-0000-0000-0000-000000000003', '{"method": "password"}', '192.168.1.3');
