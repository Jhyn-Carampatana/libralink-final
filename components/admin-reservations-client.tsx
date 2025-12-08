"use client"

import { useState, useTransition } from "react"
import { AdminReservationCard } from "@/components/admin-reservation-card"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Search } from "lucide-react"
import { fulfillReservation, cancelReservation } from "@/lib/actions/reservation-actions"
import type { ReservationWithDetails } from "@/lib/db"

interface AdminReservationsClientProps {
  initialReservations: ReservationWithDetails[]
}

export function AdminReservationsClient({ initialReservations }: AdminReservationsClientProps) {
  const [reservations, setReservations] = useState(initialReservations)
  const [searchQuery, setSearchQuery] = useState("")
  const [isPending, startTransition] = useTransition()

  const handleFulfill = (id: string) => {
    startTransition(async () => {
      const { error } = await fulfillReservation(id)
      if (!error) {
        setReservations(reservations.map((r) => (r.id === id ? { ...r, status: "fulfilled" } : r)))
      }
    })
  }

  const handleCancel = (id: string) => {
    startTransition(async () => {
      const { error } = await cancelReservation(id)
      if (!error) {
        setReservations(reservations.map((r) => (r.id === id ? { ...r, status: "cancelled" } : r)))
      }
    })
  }

  const mapToCardProps = (r: ReservationWithDetails) => ({
    id: r.id,
    bookTitle: (r.book as any)?.title || "Unknown Book",
    bookCover: (r.book as any)?.cover_url || "/abstract-book-cover.png",
    userName: (r.user as any)?.full_name || "Unknown User",
    userAvatar: (r.user as any)?.avatar_url || "/placeholder.svg",
    reservedDate: new Date(r.reserved_at).toLocaleDateString(),
    expiresDate: new Date(r.expires_at).toLocaleDateString(),
    status: r.status as any,
  })

  const filteredReservations = reservations.filter((r) => {
    const bookTitle = (r.book as any)?.title?.toLowerCase() || ""
    const userName = (r.user as any)?.full_name?.toLowerCase() || ""
    return bookTitle.includes(searchQuery.toLowerCase()) || userName.includes(searchQuery.toLowerCase())
  })

  const activeReservations = filteredReservations.filter((r) => r.status === "active")
  const fulfilledReservations = filteredReservations.filter((r) => r.status === "fulfilled")
  const expiredReservations = filteredReservations.filter((r) => r.status === "expired" || r.status === "cancelled")

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">Reservation Management</h1>
        <p className="text-muted-foreground">View and manage all book reservations</p>
      </div>

      <div className="relative mb-6 max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-5 h-5" />
        <Input
          placeholder="Search by book title or user..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 bg-input border-border"
        />
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({filteredReservations.length})
          </TabsTrigger>
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
            Expired/Cancelled ({expiredReservations.length})
          </TabsTrigger>
        </TabsList>

        {[
          { value: "all", data: filteredReservations },
          { value: "active", data: activeReservations },
          { value: "fulfilled", data: fulfilledReservations },
          { value: "expired", data: expiredReservations },
        ].map(({ value, data }) => (
          <TabsContent key={value} value={value}>
            <div className="grid gap-4">
              {data.length > 0 ? (
                data.map((r) => (
                  <AdminReservationCard
                    key={r.id}
                    {...mapToCardProps(r)}
                    onFulfill={handleFulfill}
                    onCancel={handleCancel}
                  />
                ))
              ) : (
                <div className="text-center py-16 glass-card rounded-2xl">
                  <p className="text-muted-foreground">No reservations found</p>
                </div>
              )}
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </main>
  )
}
