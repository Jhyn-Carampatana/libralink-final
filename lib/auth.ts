import { sql, type User, type UserRole } from "./db"
import { cookies } from "next/headers"
import crypto from "crypto"

// Simple password hashing (in production, use bcrypt)
function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex")
}

function verifyPassword(password: string, hash: string): boolean {
  return hashPassword(password) === hash
}

// Generate a secure random token
function generateToken(): string {
  return crypto.randomBytes(32).toString("hex")
}

// Session duration (7 days)
const SESSION_DURATION = 7 * 24 * 60 * 60 * 1000

export async function signUp(
  email: string,
  password: string,
  fullName: string,
  universityId?: string,
  universityName?: string,
  idCardUrl?: string,
): Promise<{ user: User | null; error: string | null }> {
  try {
    // Check if email already exists
    const existingUser = await sql`
      SELECT id FROM users WHERE email = ${email}
    `
    if (existingUser.length > 0) {
      return { user: null, error: "Email already registered" }
    }

    // Check if university ID already exists
    if (universityId) {
      const existingId = await sql`
        SELECT id FROM users WHERE university_id = ${universityId}
      `
      if (existingId.length > 0) {
        return { user: null, error: "University ID already registered" }
      }
    }

    const passwordHash = hashPassword(password)

    const result = await sql`
      INSERT INTO users (email, password_hash, full_name, university_id, university_name, id_card_url)
      VALUES (${email}, ${passwordHash}, ${fullName}, ${universityId || null}, ${universityName || null}, ${idCardUrl || null})
      RETURNING *
    `

    return { user: result[0] as User, error: null }
  } catch (error) {
    console.error("Sign up error:", error)
    return { user: null, error: "Failed to create account" }
  }
}

export async function signIn(
  email: string,
  password: string,
): Promise<{ user: User | null; token: string | null; error: string | null }> {
  try {
    const result = await sql`
      SELECT * FROM users WHERE email = ${email}
    `

    if (result.length === 0) {
      return { user: null, token: null, error: "Invalid email or password" }
    }

    const user = result[0] as User

    if (user.status !== "active") {
      return { user: null, token: null, error: "Account is not active" }
    }

    if (!verifyPassword(password, user.password_hash)) {
      return { user: null, token: null, error: "Invalid email or password" }
    }

    // Create session
    const token = generateToken()
    const expiresAt = new Date(Date.now() + SESSION_DURATION)

    await sql`
      INSERT INTO sessions (user_id, token, expires_at)
      VALUES (${user.id}, ${token}, ${expiresAt})
    `

    // Update last login
    await sql`
      UPDATE users SET last_login = NOW() WHERE id = ${user.id}
    `

    // Log the login
    await sql`
      INSERT INTO system_logs (user_id, action, entity_type, entity_id, details)
      VALUES (${user.id}, 'user_login', 'user', ${user.id}, '{"method": "password"}')
    `

    return { user, token, error: null }
  } catch (error) {
    console.error("Sign in error:", error)
    return { user: null, token: null, error: "Failed to sign in" }
  }
}

export async function signOut(token: string): Promise<void> {
  try {
    await sql`
      DELETE FROM sessions WHERE token = ${token}
    `
  } catch (error) {
    console.error("Sign out error:", error)
  }
}

export async function getSession(): Promise<{ user: User | null; token: string | null }> {
  try {
    const cookieStore = await cookies()
    const token = cookieStore.get("session_token")?.value

    if (!token) {
      return { user: null, token: null }
    }

    const result = await sql`
      SELECT u.* FROM users u
      INNER JOIN sessions s ON u.id = s.user_id
      WHERE s.token = ${token} AND s.expires_at > NOW()
    `

    if (result.length === 0) {
      return { user: null, token: null }
    }

    return { user: result[0] as User, token }
  } catch (error) {
    console.error("Get session error:", error)
    return { user: null, token: null }
  }
}

export async function getUserById(id: string): Promise<User | null> {
  try {
    const result = await sql`
      SELECT * FROM users WHERE id = ${id}
    `
    return result.length > 0 ? (result[0] as User) : null
  } catch (error) {
    console.error("Get user error:", error)
    return null
  }
}

export async function requireAuth(): Promise<User> {
  const { user } = await getSession()
  if (!user) {
    throw new Error("Unauthorized")
  }
  return user
}

export async function requireRole(roles: UserRole[]): Promise<User> {
  const user = await requireAuth()
  if (!roles.includes(user.role)) {
    throw new Error("Forbidden")
  }
  return user
}

export function isAdmin(user: User): boolean {
  return user.role === "admin"
}

export function isLibrarian(user: User): boolean {
  return user.role === "librarian" || user.role === "admin"
}

export function isStaff(user: User): boolean {
  return user.role === "librarian" || user.role === "admin"
}
