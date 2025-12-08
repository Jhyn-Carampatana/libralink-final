export const dynamic = "force-dynamic";
export const revalidate = 0;


import { AdminHeader } from "@/components/admin-header"
import { getReservations } from "@/lib/actions/reservation-actions"
import { AdminReservationsClient } from "@/components/admin-reservations-client"

export default async function ReservationsPage() {
  const reservations = await getReservations()

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <AdminReservationsClient initialReservations={reservations} />
    </div>
  )
}
