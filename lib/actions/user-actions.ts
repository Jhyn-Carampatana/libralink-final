"use server"

import { sql, type User, type UserRole, type UserStatus } from "@/lib/db"
import { requireRole, getSession } from "@/lib/auth"
import crypto from "crypto"

function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex")
}

export async function getUsers(role?: UserRole, search?: string): Promise<User[]> {
  await requireRole(["admin"])

  let query = `SELECT * FROM users WHERE 1=1`

  if (role) {
    query += ` AND role = '${role}'`
  }

  if (search) {
    query += ` AND (full_name ILIKE '%${search}%' OR email ILIKE '%${search}%' OR university_id ILIKE '%${search}%')`
  }

  query += ` ORDER BY created_at DESC`

  const result = await sql.unsafe(query)
  return result as User[]
}

export async function getUserById(id: string): Promise<User | null> {
  const result = await sql`SELECT * FROM users WHERE id = ${id}`
  return result.length > 0 ? (result[0] as User) : null
}

export async function getCurrentUserProfile(): Promise<User | null> {
  const { user } = await getSession()
  return user
}

export async function createUser(data: {
  email: string
  password: string
  full_name: string
  role: UserRole
  university_id?: string
  university_name?: string
  department?: string
  year_level?: string
  course?: string
}): Promise<{ user: User | null; error: string | null }> {
  try {
    await requireRole(["admin"])

    const existing = await sql`SELECT id FROM users WHERE email = ${data.email}`
    if (existing.length > 0) {
      return { user: null, error: "Email already exists" }
    }

    const passwordHash = hashPassword(data.password)

    const result = await sql`
      INSERT INTO users (email, password_hash, full_name, role, university_id, university_name, department, year_level, course)
      VALUES (
        ${data.email}, 
        ${passwordHash}, 
        ${data.full_name}, 
        ${data.role}, 
        ${data.university_id || null}, 
        ${data.university_name || null}, 
        ${data.department || null},
        ${data.year_level || null}, 
        ${data.course || null}
      )
      RETURNING *
    `

    return { user: result[0] as User, error: null }
  } catch (error) {
    console.error("Create user error:", error)
    return { user: null, error: "Failed to create user" }
  }
}

export async function updateUser(
  id: string,
  data: {
    full_name?: string
    role?: UserRole
    status?: UserStatus
    university_id?: string
    university_name?: string
    department?: string
    phone?: string
    avatar_url?: string
    year_level?: string
    course?: string
  },
): Promise<{ user: User | null; error: string | null }> {
  try {
    await requireRole(["admin"])

    const updates: string[] = []
    const values: unknown[] = []

    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined) {
        updates.push(`${key} = $${values.length + 1}`)
        values.push(value)
      }
    })

    if (updates.length === 0) {
      return { user: null, error: "No updates provided" }
    }

    values.push(id)
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${values.length} RETURNING *`
    const result = await sql.unsafe(query, values)

    return { user: result[0] as User, error: null }
  } catch (error) {
    console.error("Update user error:", error)
    return { user: null, error: "Failed to update user" }
  }
}

export async function updateUserRole(id: string, role: UserRole): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin"])
    await sql`UPDATE users SET role = ${role} WHERE id = ${id}`
    return { error: null }
  } catch (error) {
    console.error("Update role error:", error)
    return { error: "Failed to update role" }
  }
}

export async function updateUserStatus(id: string, status: UserStatus): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin"])
    await sql`UPDATE users SET status = ${status} WHERE id = ${id}`
    return { error: null }
  } catch (error) {
    console.error("Update status error:", error)
    return { error: "Failed to update status" }
  }
}

/* ----------------------------------------------------
   REPLACED deleteUser WITH SAFE SOFT DELETE
---------------------------------------------------- */

export async function deleteUser(id: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin"])

    // Soft delete instead of hard delete
    await sql`
      UPDATE users
      SET status = 'inactive'
      WHERE id = ${id}
    `

    return { error: null }
  } catch (error) {
    console.error("Soft delete user error:", error)
    return { error: "Failed to delete user" }
  }
}

export async function getUserStats() {
  const stats = await sql`
    SELECT 
      COUNT(*) as total_users,
      COUNT(*) FILTER (WHERE role = 'student') as students,
      COUNT(*) FILTER (WHERE role = 'faculty') as faculty,
      COUNT(*) FILTER (WHERE role = 'librarian') as librarians,
      COUNT(*) FILTER (WHERE role = 'admin') as admins,
      COUNT(*) FILTER (WHERE status = 'active') as active_users
    FROM users
  `
  return stats[0]
}

export async function updateCurrentUserProfile(data: {
  full_name?: string
  email?: string
}): Promise<{ user: User | null; error: string | null }> {
  try {
    const { user } = await getSession()
    if (!user) {
      return { user: null, error: "Not authenticated" }
    }

    const updates: string[] = []
    const values: unknown[] = []

    if (data.full_name) {
      updates.push(`full_name = $${values.length + 1}`)
      values.push(data.full_name)
    }

    if (data.email) {
      const existing = await sql`SELECT id FROM users WHERE email = ${data.email} AND id != ${user.id}`
      if (existing.length > 0) {
        return { user: null, error: "Email already in use" }
      }
      updates.push(`email = $${values.length + 1}`)
      values.push(data.email)
    }

    if (updates.length === 0) {
      return { user: null, error: "No updates provided" }
    }

    values.push(user.id)
    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${values.length} RETURNING *`
    const result = await sql.unsafe(query, values)

    return { user: result[0] as User, error: null }
  } catch (error) {
    console.error("Update profile error:", error)
    return { user: null, error: "Failed to update profile" }
  }
}

export async function updateCurrentUserPassword(
  currentPassword: string,
  newPassword: string,
): Promise<{ error: string | null }> {
  try {
    const { user } = await getSession()
    if (!user) {
      return { error: "Not authenticated" }
    }

    const currentHash = hashPassword(currentPassword)
    const userRecord = await sql`SELECT password_hash FROM users WHERE id = ${user.id}`

    if (userRecord.length === 0 || userRecord[0].password_hash !== currentHash) {
      return { error: "Current password is incorrect" }
    }

    const newHash = hashPassword(newPassword)
    await sql`UPDATE users SET password_hash = ${newHash} WHERE id = ${user.id}`

    return { error: null }
  } catch (error) {
    console.error("Update password error:", error)
    return { error: "Failed to change password" }
  }
}
