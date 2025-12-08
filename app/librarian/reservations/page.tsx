export const dynamic = "force-dynamic";
export const revalidate = 0;
import { LibrarianHeader } from "@/components/librarian-header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getReservations } from "@/lib/actions/reservation-actions"
import { ReservationsClient } from "@/components/reservations-client"

export default async function ReservationsPage() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const reservations = await getReservations()

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />
      <ReservationsClient initialReservations={reservations} />
    </div>
  )
}
