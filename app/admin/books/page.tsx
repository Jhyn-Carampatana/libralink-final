export const dynamic = "force-dynamic";
export const revalidate = 0;

import { AdminHeader } from "@/components/admin-header"
import { getBooks, getCategories } from "@/lib/actions/book-actions"
import { AdminBooksClient } from "@/components/admin-books-client"

export default async function AdminBooksPage() {
  const [books, categories] = await Promise.all([getBooks(), getCategories()])

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <AdminBooksClient initialBooks={books} initialCategories={categories} />
    </div>
  )
}
