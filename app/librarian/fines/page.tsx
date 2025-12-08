export const dynamic = "force-dynamic";
export const revalidate = 0;

import { LibrarianHeader } from "@/components/librarian-header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getFines } from "@/lib/actions/fine-actions"
import { FinesClient } from "@/components/fines-client"

export default async function FinesPage() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const fines = await getFines()

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />
      <FinesClient initialFines={fines} />
    </div>
  )
}
