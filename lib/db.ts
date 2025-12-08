import { neon } from "@neondatabase/serverless"

export function createClient() {
  const connectionString = process.env.DATABASE_URL
  if (!connectionString) {
    throw new Error("DATABASE_URL environment variable is not set")
  }
  return neon(connectionString)
}

export async function withRetry<T>(fn: () => Promise<T>, retries = 3, baseDelay = 100): Promise<T> {
  let lastError: Error | null = null

  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error as Error
      console.error(`[v0] Database attempt ${attempt + 1}/${retries} failed:`, error)

      if (attempt < retries - 1) {
        const delay = baseDelay * Math.pow(2, attempt)
        await new Promise((resolve) => setTimeout(resolve, delay))
      }
    }
  }

  throw lastError
}

export async function sql(strings: TemplateStringsArray, ...values: unknown[]) {
  return withRetry(async () => {
    const client = createClient()
    return await client(strings, ...values)
  })
}

sql.unsafe = async (query: string, values?: unknown[]) => {
  return withRetry(async () => {
    const client = createClient()
    const result = await client.query(query, values || [])
    return result
  })
}

// Type definitions for database entities
export type UserRole = "student" | "faculty" | "librarian" | "admin"
export type UserStatus = "active" | "inactive" | "suspended"
export type BookStatus = "available" | "borrowed" | "reserved" | "maintenance"
export type BorrowStatus = "pending" | "approved" | "declined" | "returned" | "overdue"
export type ReservationStatus = "active" | "fulfilled" | "expired" | "cancelled"
export type FineStatus = "unpaid" | "paid" | "waived"
export type FineReason = "overdue" | "damage" | "lost" | "other"

export interface User {
  id: string
  email: string
  password_hash: string
  full_name: string
  role: UserRole
  status: UserStatus
  university_id: string | null
  university_name: string | null
  department: string | null
  phone: string | null
  avatar_url: string | null
  id_card_url: string | null
  email_verified: boolean
  last_login: Date | null
  created_at: Date
  updated_at: Date
  year_level: string | null
course: string | null
}

export interface Author {
  id: string
  name: string
  bio: string | null
  avatar_url: string | null
  created_at: Date
  updated_at: Date
}

export interface Category {
  id: string
  name: string
  description: string | null
  created_at: Date
  updated_at: Date
}

export interface Publisher {
  id: string
  name: string
  address: string | null
  website: string | null
  created_at: Date
  updated_at: Date
}

export interface Book {
  id: string
  title: string
  isbn: string | null
  description: string | null
  cover_url: string | null
  publisher_id: string | null
  publication_year: number | null
  total_copies: number
  available_copies: number
  rating: number
  rating_count: number
  status: BookStatus
  created_at: Date
  updated_at: Date
}

export interface BookWithDetails extends Book {
  authors: Author[]
  categories: Category[]
  publisher: Publisher | null
}

export interface BorrowRequest {
  id: string
  user_id: string
  book_id: string
  status: BorrowStatus
  requested_at: Date
  approved_at: Date | null
  approved_by: string | null
  due_date: Date | null
  returned_at: Date | null
  notes: string | null
  created_at: Date
  updated_at: Date
}

export interface BorrowRequestWithDetails extends BorrowRequest {
  user: User
  book: Book
  approver: User | null
}

export interface Reservation {
  id: string
  user_id: string
  book_id: string
  status: ReservationStatus
  reserved_at: Date
  expires_at: Date | null
  fulfilled_at: Date | null
  cancelled_at: Date | null
  created_at: Date
  updated_at: Date
}

export interface ReservationWithDetails extends Reservation {
  user: User
  book: Book
}

export interface Fine {
  id: string
  user_id: string
  borrow_request_id: string | null
  book_id: string | null
  amount: number
  reason: FineReason
  status: FineStatus
  description: string | null
  paid_at: Date | null
  created_by: string | null
  created_at: Date
  updated_at: Date
}

export interface FineWithDetails extends Fine {
  user: User
  book: Book | null
}

export interface SystemLog {
  id: string
  user_id: string | null
  action: string
  entity_type: string | null
  entity_id: string | null
  details: Record<string, unknown> | null
  ip_address: string | null
  user_agent: string | null
  created_at: Date
}

export interface SystemLogWithUser extends SystemLog {
  user: User | null
}

export interface Session {
  id: string
  user_id: string
  token: string
  expires_at: Date
  created_at: Date
}
