"use server"

import { sql, type SystemLogWithUser } from "@/lib/db"
import { requireRole } from "@/lib/auth"

export async function getSystemLogs(
  userId?: string,
  action?: string,
  startDate?: Date,
  endDate?: Date,
): Promise<SystemLogWithUser[]> {
  try {
    await requireRole(["admin"])

    let query = `
      SELECT l.*, 
        CASE WHEN u.id IS NOT NULL THEN jsonb_build_object('id', u.id, 'full_name', u.full_name, 'email', u.email, 'role', u.role) ELSE NULL END as user
      FROM system_logs l
      LEFT JOIN users u ON l.user_id = u.id
      WHERE 1=1
    `

    if (userId) {
      query += ` AND l.user_id = '${userId}'`
    }

    if (action) {
      query += ` AND l.action ILIKE '%${action}%'`
    }

    if (startDate) {
      query += ` AND l.created_at >= '${startDate.toISOString()}'`
    }

    if (endDate) {
      query += ` AND l.created_at <= '${endDate.toISOString()}'`
    }

    query += ` ORDER BY l.created_at DESC LIMIT 100`

    const result = await sql.unsafe(query)
    return result as SystemLogWithUser[]
  } catch (error) {
    console.error("Get system logs error:", error)
    return []
  }
}

export async function createLog(data: {
  action: string
  entity_type?: string
  entity_id?: string
  details?: Record<string, unknown>
}): Promise<void> {
  try {
    const { user } = await import("@/lib/auth").then((m) => m.getSession())

    await sql`
      INSERT INTO system_logs (user_id, action, entity_type, entity_id, details)
      VALUES (${user?.id || null}, ${data.action}, ${data.entity_type || null}, ${data.entity_id || null}, ${JSON.stringify(data.details || {})})
    `
  } catch (error) {
    console.error("Create log error:", error)
  }
}
