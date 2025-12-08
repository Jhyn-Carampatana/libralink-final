"use server"

import { sql, type Book, type BookWithDetails, type Category } from "@/lib/db"
import { requireRole } from "@/lib/auth"

// --------------------
// HELPERS
// --------------------
function mapBook(b: any): BookWithDetails {
  return {
    ...b,
    authors: b.author_name ? [{ id: "1", name: b.author_name }] : [],
    categories: b.category_name ? [{ id: b.category_id, name: b.category_name }] : [],
    publisher: b.publisher_name ? { id: "1", name: b.publisher_name } : null,
  }
}

// --------------------
// BOOK QUERIES
// --------------------
export async function getBookById(id: string): Promise<BookWithDetails | null> {
  const result = (await sql`
    SELECT b.*, c.name as category_name
    FROM books b
    LEFT JOIN categories c ON b.category_id = c.id
    WHERE b.id = ${id} AND b.status != 'maintenance'
    LIMIT 1
  `) as any[]

  if (result.length === 0) return null

  return mapBook(result[0])
}

export async function getBooks(search?: string, category?: string): Promise<BookWithDetails[]> {
  let result = (await sql`
    SELECT b.*, c.name as category_name
    FROM books b
    LEFT JOIN categories c ON b.category_id = c.id
    WHERE b.status != 'maintenance'
    ORDER BY b.created_at DESC
  `) as any[]

  result = result.map(mapBook)

  if (search) {
    const q = search.toLowerCase()
    result = result.filter(
      (b) =>
        b.title.toLowerCase().includes(q) ||
        (b.author_name || "").toLowerCase().includes(q) ||
        (b.category_name || "").toLowerCase().includes(q),
    )
  }

  if (category) {
    const c = category.toLowerCase()
    result = result.filter((b) => (b.category_name || "").toLowerCase().includes(c))
  }

  return result
}

export async function getPopularBooks(limit = 6): Promise<BookWithDetails[]> {
  const result = (await sql`
    SELECT b.*, c.name as category_name
    FROM books b
    LEFT JOIN categories c ON b.category_id = c.id
    WHERE b.status != 'maintenance'
    ORDER BY b.rating DESC, b.rating_count DESC
    LIMIT ${limit}
  `) as any[]
  return result.map(mapBook)
}

export async function getFeaturedBook(): Promise<BookWithDetails | null> {
  const result = (await sql`
    SELECT b.*, c.name as category_name
    FROM books b
    LEFT JOIN categories c ON b.category_id = c.id
    WHERE b.status != 'maintenance'
    ORDER BY b.rating DESC
    LIMIT 1
  `) as any[]

  if (result.length === 0) return null
  return mapBook(result[0])
}

// --------------------
// BOOK CRUD
// --------------------
export async function createBook(data: {
  title: string
  isbn?: string
  description?: string
  cover_url?: string
  author_name?: string
  publisher_name?: string
  category_id?: string
  publication_year?: number
  total_copies: number
}): Promise<{ book: Book | null; error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    const r = await sql`
      INSERT INTO books (
        title, isbn, description, cover_url, author_name, publisher_name,
        category_id, publication_year, total_copies, available_copies
      )
      VALUES (
        ${data.title}, ${data.isbn || null}, ${data.description || null},
        ${data.cover_url || null}, ${data.author_name || "Unknown Author"},
        ${data.publisher_name || ""}, ${data.category_id || null},
        ${data.publication_year || null}, ${data.total_copies}, ${data.total_copies}
      )
      RETURNING *
    `
    return { book: r[0] as Book, error: null }
  } catch (e) {
    console.error(e)
    return { book: null, error: "Failed to create book" }
  }
}

export async function updateBook(
  id: string,
  data: {
    title?: string
    isbn?: string
    description?: string
    cover_url?: string
    author_name?: string
    publisher_name?: string
    category_id?: string
    publication_year?: number
    total_copies?: number
    available_copies?: number
    status?: string
  },
): Promise<{ book: Book | null; error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    if (data.title !== undefined) await sql`UPDATE books SET title=${data.title} WHERE id=${id}`
    if (data.isbn !== undefined) await sql`UPDATE books SET isbn=${data.isbn} WHERE id=${id}`
    if (data.description !== undefined) await sql`UPDATE books SET description=${data.description} WHERE id=${id}`
    if (data.cover_url !== undefined) await sql`UPDATE books SET cover_url=${data.cover_url} WHERE id=${id}`
    if (data.author_name !== undefined) await sql`UPDATE books SET author_name=${data.author_name} WHERE id=${id}`
    if (data.publisher_name !== undefined) await sql`UPDATE books SET publisher_name=${data.publisher_name} WHERE id=${id}`
    if (data.category_id !== undefined) await sql`UPDATE books SET category_id=${data.category_id} WHERE id=${id}`
    if (data.publication_year !== undefined)
      await sql`UPDATE books SET publication_year=${data.publication_year} WHERE id=${id}`
    if (data.total_copies !== undefined)
      await sql`UPDATE books SET total_copies=${data.total_copies} WHERE id=${id}`
    if (data.available_copies !== undefined)
      await sql`UPDATE books SET available_copies=${data.available_copies} WHERE id=${id}`
    if (data.status !== undefined) await sql`UPDATE books SET status=${data.status} WHERE id=${id}`

    const r = await sql`SELECT * FROM books WHERE id=${id}`
    return { book: r[0] as Book, error: null }
  } catch (e) {
    console.error(e)
    return { book: null, error: "Failed to update book" }
  }
}

export async function deleteBook(id: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    await sql`UPDATE books SET status='maintenance' WHERE id=${id}`
    return { error: null }
  } catch (e) {
    console.error(e)
    return { error: "Failed to delete book" }
  }
}

// --------------------
// CATEGORY CRUD
// --------------------
export async function getCategories(): Promise<Category[]> {
  const r = await sql`SELECT * FROM categories ORDER BY name ASC`
  return r as Category[]
}

export async function createCategory(data: { name: string }): Promise<{ category: Category | null; error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    const r = await sql`
      INSERT INTO categories (name)
      VALUES (${data.name})
      RETURNING *
    `
    return { category: r[0] as Category, error: null }
  } catch (e) {
    console.error(e)
    return { category: null, error: "Failed to create category" }
  }
}

export async function updateCategory(
  id: string,
  data: { name?: string },
): Promise<{ category: Category | null; error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    if (data.name !== undefined) await sql`UPDATE categories SET name=${data.name} WHERE id=${id}`
    const r = await sql`SELECT * FROM categories WHERE id=${id}`
    return { category: r[0] as Category, error: null }
  } catch (e) {
    console.error(e)
    return { category: null, error: "Failed to update category" }
  }
}

export async function deleteCategory(id: string): Promise<{ error: string | null }> {
  try {
    await requireRole(["admin", "librarian"])
    await sql`DELETE FROM categories WHERE id=${id}`
    return { error: null }
  } catch (e) {
    console.error(e)
    return { error: "Cannot delete category. Remove books using it first." }
  }
}
