"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import Image from "next/image"
import { Calendar, User, CheckCircle, XCircle } from "lucide-react"

interface AdminReservationCardProps {
  id: string
  bookTitle: string
  bookCover: string
  userName: string
  reservationDate: string
  expirationDate: string
  status: string
  onFulfill?: (id: string) => void
  onCancel?: (id: string) => void
}

export function AdminReservationCard({
  id,
  bookTitle,
  bookCover,
  userName,
  reservationDate,
  expirationDate,
  status,
  onFulfill,
  onCancel,
}: AdminReservationCardProps) {
  const getStatusColor = () => {
    switch (status) {
      case "active":
        return "bg-green-500/20 text-green-400"
      case "fulfilled":
        return "bg-blue-500/20 text-blue-400"
      case "expired":
        return "bg-red-500/20 text-red-400"
      case "cancelled":
        return "bg-gray-500/20 text-gray-400"
      default:
        return "bg-gray-500/20 text-gray-400"
    }
  }

  return (
    <Card className="glass-card p-4 hover:border-accent/50 transition-all duration-300">
      <div className="flex items-center gap-4">
        <div className="w-16 h-24 rounded-lg overflow-hidden bg-secondary flex-shrink-0">
          <Image
            src={bookCover || "/placeholder.svg"}
            alt={bookTitle}
            width={64}
            height={96}
            className="w-full h-full object-cover"
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${getStatusColor()}`}>{status}</span>
          </div>
          <h3 className="font-semibold text-foreground truncate">{bookTitle}</h3>
          <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
            <span className="flex items-center gap-1">
              <User className="w-3 h-3" />
              {userName}
            </span>
            <span className="flex items-center gap-1">
              <Calendar className="w-3 h-3" />
              Reserved: {reservationDate}
            </span>
            <span className="flex items-center gap-1">Expires: {expirationDate}</span>
          </div>
        </div>

        {status === "active" && (
          <div className="flex gap-2">
            <Button size="sm" onClick={() => onFulfill?.(id)} className="bg-green-600 hover:bg-green-700 text-white">
              <CheckCircle className="w-4 h-4 mr-1" />
              Fulfill
            </Button>
            <Button size="sm" variant="destructive" onClick={() => onCancel?.(id)}>
              <XCircle className="w-4 h-4 mr-1" />
              Cancel
            </Button>
          </div>
        )}
      </div>
    </Card>
  )
}
