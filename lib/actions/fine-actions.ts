"use server"

import { sql, type Fine, type FineWithDetails, type FineStatus, type FineReason } from "@/lib/db"
import { requireRole } from "@/lib/auth"

export async function getFines(status?: FineStatus): Promise<FineWithDetails[]> {
  try {
    let query = `
      SELECT f.*, 
        jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email, 'avatar_url', u.avatar_url) as user,
        CASE WHEN b.id IS NOT NULL THEN jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url) ELSE NULL END as book
      FROM fines f
      INNER JOIN users u ON f.user_id = u.id
      LEFT JOIN books b ON f.book_id = b.id
    `

    if (status) {
      query += ` WHERE f.status = '${status}'`
    }

    query += ` ORDER BY f.created_at DESC`

    const result = await sql.unsafe(query)
    return result as FineWithDetails[]
  } catch (error) {
    console.error("Get fines error:", error)
    return []
  }
}

export async function getUserFines(userId: string): Promise<FineWithDetails[]> {
  try {
    const result = await sql`
      SELECT f.*, 
        jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email) as user,
        CASE WHEN b.id IS NOT NULL THEN jsonb_build_object('id', b.id, 'title', b.title, 'cover_url', b.cover_url) ELSE NULL END as book
      FROM fines f
      INNER JOIN users u ON f.user_id = u.id
      LEFT JOIN books b ON f.book_id = b.id
      WHERE f.user_id = ${userId}
      ORDER BY f.created_at DESC
    `
    return result as FineWithDetails[]
  } catch (error) {
    console.error("Get user fines error:", error)
    return []
  }
}

export async function createFine(data: {
  user_id: string
  book_id?: string
  amount: number
  reason: FineReason
  description?: string
}): Promise<{ fine: Fine | null; error: string | null }> {
  try {
    const user = await requireRole(["librarian", "admin"])

    const result = await sql`
      INSERT INTO fines (user_id, book_id, amount, reason, description, created_by)
      VALUES (${data.user_id}, ${data.book_id || null}, ${data.amount}, ${data.reason}, ${data.description || null}, ${user.id})
      RETURNING *
    `

    return { fine: result[0] as Fine, error: null }
  } catch (error) {
    console.error("Create fine error:", error)
    return { fine: null, error: "Failed to create fine" }
  }
}

export async function updateFine(
  id: string,
  data: { amount?: number; reason?: FineReason; description?: string },
): Promise<{ error: string | null }> {
  try {
    await requireRole(["librarian", "admin"])

    const updates: string[] = []
    const values: unknown[] = []

    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined) {
        updates.push(`${key} = $${values.length + 1}`)
        values.push(value)
      }
    })

    if (updates.length === 0) {
      return { error: "No updates provided" }
    }

    values.push(id)
    const query = `UPDATE fines SET ${updates.join(", ")} WHERE id = $${values.length}`
    await sql.unsafe(query, values)

    return { error: null }
  } catch (error) {
    console.error("Update fine error:", error)
    return { error: "Failed to update fine" }
  }
}

export async function markFinePaid(fineId: string): Promise<{ error: string | null }> {
  try {
    const user = await requireRole(["librarian", "admin"])

    await sql`
      UPDATE fines SET status = 'paid', paid_at = NOW() WHERE id = ${fineId}
    `

    // Log the action
    await sql`
      INSERT INTO system_logs (user_id, action, entity_type, entity_id, details)
      VALUES (${user.id}, 'fine_paid', 'fine', ${fineId}, '{}')
    `

    return { error: null }
  } catch (error) {
    console.error("Mark fine paid error:", error)
    return { error: "Failed to mark fine as paid" }
  }
}

export async function deleteFine(id: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["librarian", "admin"])
    await sql`DELETE FROM fines WHERE id = ${id}`
    return { error: null }
  } catch (error) {
    console.error("Delete fine error:", error)
    return { error: "Failed to delete fine" }
  }
}

export async function getFineStats() {
  try {
    const stats = await sql`
      SELECT 
        COUNT(*) as total_fines,
        COUNT(*) FILTER (WHERE status = 'unpaid') as unpaid,
        COUNT(*) FILTER (WHERE status = 'paid') as paid,
        COALESCE(SUM(amount) FILTER (WHERE status = 'unpaid'), 0) as unpaid_amount,
        COALESCE(SUM(amount) FILTER (WHERE status = 'paid'), 0) as paid_amount
      FROM fines
    `
    return stats[0]
  } catch (error) {
    console.error("Get fine stats error:", error)
    return { total_fines: 0, unpaid: 0, paid: 0, unpaid_amount: 0, paid_amount: 0 }
  }
}
