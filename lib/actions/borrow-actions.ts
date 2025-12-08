"use server"

import { sql, type BorrowRequest, type BorrowRequestWithDetails, type BorrowStatus } from "@/lib/db"
import { requireRole, getSession } from "@/lib/auth"

export async function getBorrowRequests(status?: BorrowStatus): Promise<BorrowRequestWithDetails[]> {
  let query = `
    SELECT br.*, 
      jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email, 'avatar_url', u.avatar_url, 'university_id', u.university_id) as user,
      jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url, 'isbn', b.isbn) as book,
      CASE WHEN ap.id IS NOT NULL THEN jsonb_build_object('id', ap.id, 'full_name', ap.full_name) ELSE NULL END as approver
    FROM borrow_requests br
    INNER JOIN users u ON br.user_id = u.id
    INNER JOIN books b ON br.book_id = b.id AND b.status != 'maintenance'
    LEFT JOIN users ap ON br.approved_by = ap.id
  `

  if (status) {
    query += ` WHERE br.status = '${status}'`
  }

  query += ` ORDER BY br.requested_at DESC`

  const result = await sql.unsafe(query)
  return result as BorrowRequestWithDetails[]
}

export async function getUserBorrowedBooks(userId: string): Promise<BorrowRequestWithDetails[]> {
  const result = await sql`
    SELECT br.*, 
      jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email, 'avatar_url', u.avatar_url) as user,
      jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url, 'isbn', b.isbn) as book,
      CASE WHEN ap.id IS NOT NULL THEN jsonb_build_object('id', ap.id, 'full_name', ap.full_name) ELSE NULL END as approver
    FROM borrow_requests br
    INNER JOIN users u ON br.user_id = u.id
    INNER JOIN books b ON br.book_id = b.id AND b.status != 'maintenance'
    LEFT JOIN users ap ON br.approved_by = ap.id
    WHERE br.user_id = ${userId} AND br.status IN ('approved', 'overdue')
    ORDER BY br.approved_at DESC
  `
  return result as BorrowRequestWithDetails[]
}

export async function createBorrowRequest(
  bookId: string,
): Promise<{ request: BorrowRequest | null; error: string | null }> {
  try {
    const { user } = await getSession()
    if (!user) {
      return { request: null, error: "Not authenticated" }
    }

    // Check if book is available and not deleted
    const book = await sql`SELECT available_copies, status FROM books WHERE id = ${bookId}`
    if (book.length === 0) {
      return { request: null, error: "Book not found" }
    }
    if (book[0].status === "maintenance") {
      return { request: null, error: "This book is no longer available" }
    }
    if (book[0].available_copies <= 0) {
      return { request: null, error: "No copies available" }
    }

    // Check for existing pending request
    const existing = await sql`
      SELECT id FROM borrow_requests 
      WHERE user_id = ${user.id} AND book_id = ${bookId} AND status = 'pending'
    `
    if (existing.length > 0) {
      return { request: null, error: "You already have a pending request for this book" }
    }

    const result = await sql`
      INSERT INTO borrow_requests (user_id, book_id, status)
      VALUES (${user.id}, ${bookId}, 'pending')
      RETURNING *
    `

    return { request: result[0] as BorrowRequest, error: null }
  } catch (error) {
    console.error("Create borrow request error:", error)
    return { request: null, error: "Failed to create request" }
  }
}

export async function approveBorrowRequest(requestId: string, dueDate: Date): Promise<{ error: string | null }> {
  try {
    const user = await requireRole(["librarian", "admin"])

    const request = await sql`SELECT * FROM borrow_requests WHERE id = ${requestId}`
    if (request.length === 0) {
      return { error: "Request not found" }
    }

    const bookId = request[0].book_id

    await sql`
      UPDATE borrow_requests 
      SET status = 'approved', approved_at = NOW(), approved_by = ${user.id}, due_date = ${dueDate}
      WHERE id = ${requestId}
    `

    await sql`
      UPDATE books SET available_copies = available_copies - 1 WHERE id = ${bookId}
    `

    await sql`
      INSERT INTO system_logs (user_id, action, entity_type, entity_id, details)
      VALUES (${user.id}, 'borrow_approved', 'borrow_request', ${requestId}, '{}')
    `

    return { error: null }
  } catch (error) {
    console.error("Approve borrow request error:", error)
    return { error: "Failed to approve request" }
  }
}

export async function declineBorrowRequest(requestId: string, reason?: string): Promise<{ error: string | null }> {
  try {
    const user = await requireRole(["librarian", "admin"])

    await sql`
      UPDATE borrow_requests 
      SET status = 'declined', approved_by = ${user.id}, notes = ${reason || null}
      WHERE id = ${requestId}
    `

    return { error: null }
  } catch (error) {
    console.error("Decline borrow request error:", error)
    return { error: "Failed to decline request" }
  }
}

export async function returnBook(requestId: string): Promise<{ fine: number | null; error: string | null }> {
  try {
    const user = await requireRole(["librarian", "admin"])

    const request = await sql`SELECT * FROM borrow_requests WHERE id = ${requestId}`
    if (request.length === 0) {
      return { fine: null, error: "Request not found" }
    }

    const req = request[0]
    const bookId = req.book_id
    const userId = req.user_id
    const dueDate = new Date(req.due_date)
    const now = new Date()

    let fineAmount = 0
    if (now > dueDate) {
      const daysOverdue = Math.ceil((now.getTime() - dueDate.getTime()) / (1000 * 60 * 60 * 24))
      fineAmount = daysOverdue * 0.5
    }

    await sql`
      UPDATE borrow_requests 
      SET status = 'returned', returned_at = NOW()
      WHERE id = ${requestId}
    `

    await sql`
      UPDATE books SET available_copies = available_copies + 1 WHERE id = ${bookId}
    `

    if (fineAmount > 0) {
      await sql`
        INSERT INTO fines (user_id, borrow_request_id, book_id, amount, reason, description, created_by)
        VALUES (${userId}, ${requestId}, ${bookId}, ${fineAmount}, 'overdue', 'Late return fine', ${user.id})
      `
    }

    await sql`
      INSERT INTO system_logs (user_id, action, entity_type, entity_id, details)
      VALUES (${user.id}, 'book_returned', 'borrow_request', ${requestId}, ${JSON.stringify({ fine: fineAmount })})
    `

    return { fine: fineAmount, error: null }
  } catch (error) {
    console.error("Return book error:", error)
    return { fine: null, error: "Failed to return book" }
  }
}

export async function getBorrowStats() {
  try {
    const stats = await sql`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'approved') as active,
        COUNT(*) FILTER (WHERE status = 'approved' AND due_date < CURRENT_DATE) as overdue,
        COUNT(*) FILTER (WHERE status = 'returned') as returned
      FROM borrow_requests
    `
    return stats[0]
  } catch (error) {
    console.error("Get borrow stats error:", error)
    return { pending: 0, active: 0, overdue: 0, returned: 0 }
  }
}
