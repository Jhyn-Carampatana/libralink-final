"use client"

import { useState } from "react"
import { ReservationCard } from "@/components/reservation-card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { fulfillReservation, cancelReservation } from "@/lib/actions/reservation-actions"
import type { ReservationWithDetails } from "@/lib/db"

interface ReservationsClientProps {
  initialReservations: ReservationWithDetails[]
}

export function ReservationsClient({ initialReservations }: ReservationsClientProps) {
  const [reservationList, setReservationList] = useState(initialReservations)

  const handleFulfill = async (id: string) => {
    const result = await fulfillReservation(id)
    if (!result.error) {
      setReservationList(reservationList.map((res) => (res.id === id ? { ...res, status: "fulfilled" as const } : res)))
    }
  }

  const handleCancel = async (id: string) => {
    const result = await cancelReservation(id)
    if (!result.error) {
      setReservationList(reservationList.map((res) => (res.id === id ? { ...res, status: "cancelled" as const } : res)))
    }
  }

  const activeReservations = reservationList.filter((r) => r.status === "active")
  const fulfilledReservations = reservationList.filter((r) => r.status === "fulfilled")
  const expiredReservations = reservationList.filter((r) => r.status === "expired" || r.status === "cancelled")

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">Reservations</h1>
        <p className="text-muted-foreground">Manage book reservations from students</p>
      </div>

      <Tabs defaultValue="active" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger
            value="active"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Active ({activeReservations.length})
          </TabsTrigger>
          <TabsTrigger
            value="fulfilled"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Fulfilled ({fulfilledReservations.length})
          </TabsTrigger>
          <TabsTrigger
            value="expired"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Expired ({expiredReservations.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="active">
          <div className="grid gap-4">
            {activeReservations.length > 0 ? (
              activeReservations.map((reservation: any) => (
                <ReservationCard
                  key={reservation.id}
                  id={reservation.id}
                  bookTitle={reservation.book?.title || "Unknown Book"}
                  bookCover={reservation.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={reservation.user?.full_name || "Unknown Student"}
                  reservationDate={new Date(reservation.reserved_at).toLocaleDateString()}
                  expirationDate={new Date(reservation.expires_at).toLocaleDateString()}
                  status="active"
                  onFulfill={handleFulfill}
                  onCancel={handleCancel}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No active reservations</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="fulfilled">
          <div className="grid gap-4">
            {fulfilledReservations.length > 0 ? (
              fulfilledReservations.map((reservation: any) => (
                <ReservationCard
                  key={reservation.id}
                  id={reservation.id}
                  bookTitle={reservation.book?.title || "Unknown Book"}
                  bookCover={reservation.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={reservation.user?.full_name || "Unknown Student"}
                  reservationDate={new Date(reservation.reserved_at).toLocaleDateString()}
                  expirationDate={new Date(reservation.expires_at).toLocaleDateString()}
                  status="fulfilled"
                  onFulfill={handleFulfill}
                  onCancel={handleCancel}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No fulfilled reservations</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="expired">
          <div className="grid gap-4">
            {expiredReservations.length > 0 ? (
              expiredReservations.map((reservation: any) => (
                <ReservationCard
                  key={reservation.id}
                  id={reservation.id}
                  bookTitle={reservation.book?.title || "Unknown Book"}
                  bookCover={reservation.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={reservation.user?.full_name || "Unknown Student"}
                  reservationDate={new Date(reservation.reserved_at).toLocaleDateString()}
                  expirationDate={new Date(reservation.expires_at).toLocaleDateString()}
                  status="expired"
                  onFulfill={handleFulfill}
                  onCancel={handleCancel}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No expired reservations</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </main>
  )
}
