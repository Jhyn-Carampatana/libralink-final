export const dynamic = "force-dynamic";
export const revalidate = 0;


import { LibrarianHeader } from "@/components/librarian-header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getBooks } from "@/lib/actions/book-actions"
import { ManageBooksClient } from "@/components/manage-books-client"

export default async function ManageBooksPage() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const books = await getBooks()

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />
      <ManageBooksClient initialBooks={books} />
    </div>
  )
}
