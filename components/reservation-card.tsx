"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Calendar, Clock, CheckCircle, XCircle, AlertTriangle } from "lucide-react"

interface ReservationCardProps {
  id: string
  bookTitle: string
  bookCover: string
  studentName: string
  reservationDate: string
  expirationDate: string
  status: "active" | "expired" | "fulfilled"
  onFulfill: (id: string) => void
  onCancel: (id: string) => void
}

export function ReservationCard({
  id,
  bookTitle,
  bookCover,
  studentName,
  reservationDate,
  expirationDate,
  status,
  onFulfill,
  onCancel,
}: ReservationCardProps) {
  const statusConfig = {
    active: { icon: Clock, color: "text-blue-400", bg: "bg-blue-400/10", label: "Active" },
    expired: { icon: AlertTriangle, color: "text-red-400", bg: "bg-red-400/10", label: "Expired" },
    fulfilled: { icon: CheckCircle, color: "text-green-400", bg: "bg-green-400/10", label: "Fulfilled" },
  }

  const { icon: StatusIcon, color, bg, label } = statusConfig[status]

  return (
    <Card className="glass-card p-4 flex gap-4 hover:border-accent/30 transition-all">
      {/* Book Cover */}
      <div className="w-20 h-28 rounded-lg overflow-hidden flex-shrink-0 bg-secondary">
        <img src={bookCover || "/placeholder.svg"} alt={bookTitle} className="w-full h-full object-cover" />
      </div>

      {/* Content */}
      <div className="flex-1 flex flex-col justify-between">
        <div>
          <h3 className="font-semibold text-foreground text-base mb-1">{bookTitle}</h3>
          <p className="text-sm text-muted-foreground">
            Reserved by: <span className="text-foreground">{studentName}</span>
          </p>

          <div className="flex flex-wrap gap-4 mt-2 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5" />
              <span>Reserved: {reservationDate}</span>
            </div>
            <div className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              <span>Expires: {expirationDate}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between mt-3">
          <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md ${bg}`}>
            <StatusIcon className={`w-3.5 h-3.5 ${color}`} />
            <span className={`text-xs font-medium ${color}`}>{label}</span>
          </div>

          {status === "active" && (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                className="text-green-400 border-green-400/30 hover:bg-green-400/10 hover:text-green-300 bg-transparent"
                onClick={() => onFulfill(id)}
              >
                <CheckCircle className="w-4 h-4 mr-1" />
                Fulfill
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-red-400 border-red-400/30 hover:bg-red-400/10 hover:text-red-300 bg-transparent"
                onClick={() => onCancel(id)}
              >
                <XCircle className="w-4 h-4 mr-1" />
                Cancel
              </Button>
            </div>
          )}
        </div>
      </div>
    </Card>
  )
}
