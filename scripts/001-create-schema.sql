-- LibraLink Database Schema
-- This script creates all tables for the library management system

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================
-- ENUM TYPES
-- =====================

CREATE TYPE user_role AS ENUM ('student', 'faculty', 'librarian', 'admin');
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended');
CREATE TYPE book_status AS ENUM ('available', 'borrowed', 'reserved', 'maintenance');
CREATE TYPE borrow_status AS ENUM ('pending', 'approved', 'declined', 'returned', 'overdue');
CREATE TYPE reservation_status AS ENUM ('active', 'fulfilled', 'expired', 'cancelled');
CREATE TYPE fine_status AS ENUM ('unpaid', 'paid', 'waived');
CREATE TYPE fine_reason AS ENUM ('overdue', 'damage', 'lost', 'other');

-- =====================
-- USERS TABLE
-- =====================

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255) NOT NULL,
  role user_role NOT NULL DEFAULT 'student',
  status user_status NOT NULL DEFAULT 'active',
  university_id VARCHAR(50) UNIQUE,
  university_name VARCHAR(255),
  department VARCHAR(255),
  phone VARCHAR(20),
  avatar_url TEXT,
  id_card_url TEXT,
  email_verified BOOLEAN DEFAULT FALSE,
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- AUTHORS TABLE
-- =====================

CREATE TABLE authors (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  bio TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- CATEGORIES TABLE
-- =====================

CREATE TABLE categories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- PUBLISHERS TABLE
-- =====================

CREATE TABLE publishers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(255) NOT NULL,
  address TEXT,
  website VARCHAR(255),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- BOOKS TABLE
-- =====================

CREATE TABLE books (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title VARCHAR(255) NOT NULL,
  isbn VARCHAR(20) UNIQUE,
  description TEXT,
  cover_url TEXT,
  publisher_id UUID REFERENCES publishers(id) ON DELETE SET NULL,
  publication_year INTEGER,
  total_copies INTEGER NOT NULL DEFAULT 1,
  available_copies INTEGER NOT NULL DEFAULT 1,
  rating DECIMAL(2,1) DEFAULT 0,
  rating_count INTEGER DEFAULT 0,
  status book_status NOT NULL DEFAULT 'available',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CONSTRAINT valid_copies CHECK (available_copies >= 0 AND available_copies <= total_copies)
);

-- =====================
-- BOOK_AUTHORS (Many-to-Many)
-- =====================

CREATE TABLE book_authors (
  book_id UUID REFERENCES books(id) ON DELETE CASCADE,
  author_id UUID REFERENCES authors(id) ON DELETE CASCADE,
  PRIMARY KEY (book_id, author_id)
);

-- =====================
-- BOOK_CATEGORIES (Many-to-Many)
-- =====================

CREATE TABLE book_categories (
  book_id UUID REFERENCES books(id) ON DELETE CASCADE,
  category_id UUID REFERENCES categories(id) ON DELETE CASCADE,
  PRIMARY KEY (book_id, category_id)
);

-- =====================
-- BORROW_REQUESTS TABLE
-- =====================

CREATE TABLE borrow_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id UUID NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  status borrow_status NOT NULL DEFAULT 'pending',
  requested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  approved_at TIMESTAMP WITH TIME ZONE,
  approved_by UUID REFERENCES users(id),
  due_date DATE,
  returned_at TIMESTAMP WITH TIME ZONE,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- RESERVATIONS TABLE
-- =====================

CREATE TABLE reservations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id UUID NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  status reservation_status NOT NULL DEFAULT 'active',
  reserved_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
  fulfilled_at TIMESTAMP WITH TIME ZONE,
  cancelled_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- FINES TABLE
-- =====================

CREATE TABLE fines (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  borrow_request_id UUID REFERENCES borrow_requests(id) ON DELETE SET NULL,
  book_id UUID REFERENCES books(id) ON DELETE SET NULL,
  amount DECIMAL(10,2) NOT NULL,
  reason fine_reason NOT NULL DEFAULT 'overdue',
  status fine_status NOT NULL DEFAULT 'unpaid',
  description TEXT,
  paid_at TIMESTAMP WITH TIME ZONE,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- SYSTEM_LOGS TABLE
-- =====================

CREATE TABLE system_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(255) NOT NULL,
  entity_type VARCHAR(100),
  entity_id UUID,
  details JSONB,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- SESSIONS TABLE (for auth)
-- =====================

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================
-- INDEXES
-- =====================

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_university_id ON users(university_id);

CREATE INDEX idx_books_title ON books(title);
CREATE INDEX idx_books_isbn ON books(isbn);
CREATE INDEX idx_books_status ON books(status);

CREATE INDEX idx_borrow_requests_user ON borrow_requests(user_id);
CREATE INDEX idx_borrow_requests_book ON borrow_requests(book_id);
CREATE INDEX idx_borrow_requests_status ON borrow_requests(status);

CREATE INDEX idx_reservations_user ON reservations(user_id);
CREATE INDEX idx_reservations_book ON reservations(book_id);
CREATE INDEX idx_reservations_status ON reservations(status);

CREATE INDEX idx_fines_user ON fines(user_id);
CREATE INDEX idx_fines_status ON fines(status);

CREATE INDEX idx_system_logs_user ON system_logs(user_id);
CREATE INDEX idx_system_logs_action ON system_logs(action);
CREATE INDEX idx_system_logs_created ON system_logs(created_at);

CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- =====================
-- TRIGGERS FOR UPDATED_AT
-- =====================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_authors_updated_at BEFORE UPDATE ON authors
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_categories_updated_at BEFORE UPDATE ON categories
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_publishers_updated_at BEFORE UPDATE ON publishers
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_books_updated_at BEFORE UPDATE ON books
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_borrow_requests_updated_at BEFORE UPDATE ON borrow_requests
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reservations_updated_at BEFORE UPDATE ON reservations
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_fines_updated_at BEFORE UPDATE ON fines
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
