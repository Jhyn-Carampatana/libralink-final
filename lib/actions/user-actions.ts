"use server";

import { sql, type User, type UserRole, type UserStatus } from "@/lib/db";
import { requireRole, getSession } from "@/lib/auth";
import crypto from "crypto";

function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

/* ======================================================
   GET USERS (EXCLUDES INACTIVE USERS)
====================================================== */
export async function getUsers(role?: UserRole, search?: string): Promise<User[]> {
  await requireRole(["admin"]);

  let query = `SELECT * FROM users WHERE status != 'inactive'`;

  if (role) query += ` AND role = '${role}'`;

  if (search) {
    const s = search.toLowerCase();
    query += ` AND (LOWER(full_name) LIKE '%${s}%' OR LOWER(email) LIKE '%${s}%' OR LOWER(university_id) LIKE '%${s}%')`;
  }

  query += ` ORDER BY created_at DESC`;

  const result = await sql.unsafe(query);
  return result as User[];
}

/* ======================================================
   GET USER BY ID
====================================================== */
export async function getUserById(id: string): Promise<User | null> {
  const result = await sql`SELECT * FROM users WHERE id = ${id}`;
  return result.length > 0 ? (result[0] as User) : null;
}

/* ======================================================
   CURRENT USER PROFILE
====================================================== */
export async function getCurrentUserProfile(): Promise<User | null> {
  const { user } = await getSession();
  return user;
}

/* ======================================================
   CREATE USER
====================================================== */
export async function createUser(data: {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
  university_id?: string;
  university_name?: string;
  department?: string;
  year_level?: string;
  course?: string;
}): Promise<{ user: User | null; error: string | null }> {
  try {
    await requireRole(["admin"]);

    const exists = await sql`SELECT id FROM users WHERE email = ${data.email}`;
    if (exists.length > 0)
      return { user: null, error: "Email already exists" };

    const passwordHash = hashPassword(data.password);

    const result = await sql`
      INSERT INTO users (
        email, password_hash, full_name, role, university_id, university_name,
        department, year_level, course
      ) VALUES (
        ${data.email}, ${passwordHash}, ${data.full_name}, ${data.role},
        ${data.university_id || null}, ${data.university_name || null},
        ${data.department || null}, ${data.year_level || null}, ${data.course || null}
      )
      RETURNING *
    `;

    return { user: result[0] as User, error: null };
  } catch (err) {
    console.error("Create user error:", err);
    return { user: null, error: "Failed to create user" };
  }
}

/* ======================================================
   UPDATE USER
====================================================== */
export async function updateUser(
  id: string,
  data: Partial<{
    full_name: string;
    role: UserRole;
    status: UserStatus;
    university_id: string;
    university_name: string;
    department: string;
    phone: string;
    avatar_url: string;
    year_level: string;
    course: string;
  }>
): Promise<{ user: User | null; error: string | null }> {
  try {
    await requireRole(["admin"]);

    const updates: string[] = [];
    const values: unknown[] = [];

    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined) {
        updates.push(`${key} = $${values.length + 1}`);
        values.push(value);
      }
    });

    if (updates.length === 0) return { user: null, error: "No updates provided" };

    values.push(id);

    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${values.length} RETURNING *`;
    const result = await sql.unsafe(query, values);

    return { user: result[0] as User, error: null };
  } catch (err) {
    console.error("Update user error:", err);
    return { user: null, error: "Failed to update user" };
  }
}

/* ======================================================
   UPDATE ROLE
====================================================== */
export async function updateUserRole(id: string, role: UserRole) {
  try {
    await requireRole(["admin"]);
    await sql`UPDATE users SET role = ${role} WHERE id = ${id}`;
    return { error: null };
  } catch (err) {
    console.error("Update role error:", err);
    return { error: "Failed to update role" };
  }
}

/* ======================================================
   UPDATE STATUS (ACTIVE/SUSPENDED)
====================================================== */
export async function updateUserStatus(id: string, status: UserStatus) {
  try {
    await requireRole(["admin"]);
    await sql`UPDATE users SET status = ${status} WHERE id = ${id}`;
    return { error: null };
  } catch (err) {
    console.error("Update status error:", err);
    return { error: "Failed to update status" };
  }
}

/* ======================================================
   PERMANENT DELETE USER
====================================================== */
export async function deleteUser(id: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin"]);

    // Hard delete user
    await sql`DELETE FROM users WHERE id = ${id}`;

    return { error: null };
  } catch (err) {
    console.error("Delete user error:", err);
    return { error: "Failed to delete user" };
  }
}

/* ======================================================
   USER STATS
====================================================== */
export async function getUserStats() {
  const stats = await sql`
    SELECT 
      COUNT(*) AS total_users,
      COUNT(*) FILTER (WHERE role = 'student') AS students,
      COUNT(*) FILTER (WHERE role = 'faculty') AS faculty,
      COUNT(*) FILTER (WHERE role = 'librarian') AS librarians,
      COUNT(*) FILTER (WHERE role = 'admin') AS admins,
      COUNT(*) FILTER (WHERE status = 'active') AS active_users
    FROM users
  `;
  return stats[0];
}

/* ======================================================
   PROFILE UPDATE
====================================================== */
export async function updateCurrentUserProfile(data: {
  full_name?: string;
  email?: string;
}) {
  try {
    const { user } = await getSession();
    if (!user) return { user: null, error: "Not authenticated" };

    const updates: string[] = [];
    const values: unknown[] = [];

    if (data.full_name) {
      updates.push(`full_name = $1`);
      values.push(data.full_name);
    }

    if (data.email) {
      const exists = await sql`
        SELECT id FROM users WHERE email = ${data.email} AND id != ${user.id}
      `;
      if (exists.length > 0)
        return { user: null, error: "Email already in use" };

      updates.push(`email = $${values.length + 1}`);
      values.push(data.email);
    }

    if (updates.length === 0)
      return { user: null, error: "No updates provided" };

    values.push(user.id);

    const query = `UPDATE users SET ${updates.join(", ")} WHERE id = $${values.length} RETURNING *`;
    const result = await sql.unsafe(query, values);

    return { user: result[0] as User, error: null };
  } catch (err) {
    console.error("Update profile error:", err);
    return { user: null, error: "Failed to update profile" };
  }
}

/* ======================================================
   CHANGE PASSWORD
====================================================== */
export async function updateCurrentUserPassword(currentPassword: string, newPassword: string) {
  try {
    const { user } = await getSession();
    if (!user) return { error: "Not authenticated" };

    const currentHash = hashPassword(currentPassword);
    const stored = await sql`SELECT password_hash FROM users WHERE id = ${user.id}`;

    if (stored.length === 0 || stored[0].password_hash !== currentHash)
      return { error: "Current password is incorrect" };

    const newHash = hashPassword(newPassword);

    await sql`UPDATE users SET password_hash = ${newHash} WHERE id = ${user.id}`;

    return { error: null };
  } catch (err) {
    console.error("Update password error:", err);
    return { error: "Failed to change password" };
  }
}
