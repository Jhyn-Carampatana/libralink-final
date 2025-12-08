"use server"

import { sql, type Reservation, type ReservationWithDetails, type ReservationStatus } from "@/lib/db"
import { requireRole, getSession } from "@/lib/auth"

export async function getReservations(status?: ReservationStatus): Promise<ReservationWithDetails[]> {
  try {
    let query = `
      SELECT r.*, 
        jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email, 'avatar_url', u.avatar_url) as user,
        jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url, 'available_copies', b.available_copies) as book
      FROM reservations r
      INNER JOIN users u ON r.user_id = u.id
      INNER JOIN books b ON r.book_id = b.id AND b.status != 'maintenance'
    `

    if (status) {
      query += ` WHERE r.status = '${status}'`
    }

    query += ` ORDER BY r.reserved_at DESC`

    const result = await sql.unsafe(query)
    return result as ReservationWithDetails[]
  } catch (error) {
    console.error("Get reservations error:", error)
    return []
  }
}

export async function getUserReservations(userId: string): Promise<ReservationWithDetails[]> {
  try {
    const result = await sql`
      SELECT r.*, 
        jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email) as user,
        jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url) as book
      FROM reservations r
      INNER JOIN users u ON r.user_id = u.id
      INNER JOIN books b ON r.book_id = b.id AND b.status != 'maintenance'
      WHERE r.user_id = ${userId}
      ORDER BY r.reserved_at DESC
    `
    return result as ReservationWithDetails[]
  } catch (error) {
    console.error("Get user reservations error:", error)
    return []
  }
}

export async function createReservation(
  bookId: string,
): Promise<{ reservation: Reservation | null; error: string | null }> {
  try {
    const { user } = await getSession()
    if (!user) {
      return { reservation: null, error: "Not authenticated" }
    }

    // Check if book exists and is not deleted
    const book = await sql`SELECT status FROM books WHERE id = ${bookId}`
    if (book.length === 0) {
      return { reservation: null, error: "Book not found" }
    }
    if (book[0].status === "maintenance") {
      return { reservation: null, error: "This book is no longer available" }
    }

    // Check for existing active reservation
    const existing = await sql`
      SELECT id FROM reservations 
      WHERE user_id = ${user.id} AND book_id = ${bookId} AND status = 'active'
    `
    if (existing.length > 0) {
      return { reservation: null, error: "You already have an active reservation for this book" }
    }

    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 7)

    const result = await sql`
      INSERT INTO reservations (user_id, book_id, expires_at)
      VALUES (${user.id}, ${bookId}, ${expiresAt})
      RETURNING *
    `

    return { reservation: result[0] as Reservation, error: null }
  } catch (error) {
    console.error("Create reservation error:", error)
    return { reservation: null, error: "Failed to create reservation" }
  }
}

export async function fulfillReservation(reservationId: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["librarian", "admin"])

    await sql`
      UPDATE reservations 
      SET status = 'fulfilled', fulfilled_at = NOW()
      WHERE id = ${reservationId}
    `

    return { error: null }
  } catch (error) {
    console.error("Fulfill reservation error:", error)
    return { error: "Failed to fulfill reservation" }
  }
}

export async function cancelReservation(reservationId: string): Promise<{ error: string | null }> {
  try {
    await sql`
      UPDATE reservations 
      SET status = 'cancelled', cancelled_at = NOW()
      WHERE id = ${reservationId}
    `

    return { error: null }
  } catch (error) {
    console.error("Cancel reservation error:", error)
    return { error: "Failed to cancel reservation" }
  }
}

export async function getReservationStats() {
  try {
    const stats = await sql`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'active') as active,
        COUNT(*) FILTER (WHERE status = 'fulfilled') as fulfilled,
        COUNT(*) FILTER (WHERE status = 'expired') as expired,
        COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled
      FROM reservations
    `
    return stats[0]
  } catch (error) {
    console.error("Get reservation stats error:", error)
    return { active: 0, fulfilled: 0, expired: 0, cancelled: 0 }
  }
}
