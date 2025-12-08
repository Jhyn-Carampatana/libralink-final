export const dynamic = "force-dynamic";
export const revalidate = 0;

import { LibrarianHeader } from "@/components/librarian-header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getBorrowRequests } from "@/lib/actions/borrow-actions"
import { BorrowRequestsClient } from "@/components/borrow-requests-client"

export default async function BorrowRequestsPage() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const requests = await getBorrowRequests()

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />
      <BorrowRequestsClient initialRequests={requests} />
    </div>
  )
}
