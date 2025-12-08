export const dynamic = "force-dynamic";
export const revalidate = 0;

import { LibrarianHeader } from "@/components/librarian-header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getBorrowRequests } from "@/lib/actions/borrow-actions"
import { BorrowedBooksClient } from "@/components/borrowed-books-client"

export default async function BorrowedBooksPage() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const allRequests = await getBorrowRequests()
  const borrowedBooks = allRequests.filter((r) => r.status === "approved")

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />
      <BorrowedBooksClient initialBooks={borrowedBooks} />
    </div>
  )
}
