"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Check, X, Clock, CheckCircle, XCircle } from "lucide-react"

interface BorrowRequestCardProps {
  id: string
  bookTitle: string
  bookCover: string
  studentName: string
  studentEmail: string
  requestDate: string
  status: "pending" | "approved" | "declined"
  onApprove: (id: string) => void
  onDecline: (id: string) => void
}

export function BorrowRequestCard({
  id,
  bookTitle,
  bookCover,
  studentName,
  studentEmail,
  requestDate,
  status,
  onApprove,
  onDecline,
}: BorrowRequestCardProps) {
  const statusConfig = {
    pending: { icon: Clock, color: "text-yellow-400", bg: "bg-yellow-400/10", label: "Pending" },
    approved: { icon: CheckCircle, color: "text-green-400", bg: "bg-green-400/10", label: "Approved" },
    declined: { icon: XCircle, color: "text-red-400", bg: "bg-red-400/10", label: "Declined" },
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
            Requested by: <span className="text-foreground">{studentName}</span>
          </p>
          <p className="text-xs text-muted-foreground">{studentEmail}</p>
          <p className="text-xs text-muted-foreground mt-1">Date: {requestDate}</p>
        </div>

        <div className="flex items-center justify-between mt-3">
          <div className={`flex items-center gap-1.5 px-2 py-1 rounded-md ${bg}`}>
            <StatusIcon className={`w-3.5 h-3.5 ${color}`} />
            <span className={`text-xs font-medium ${color}`}>{label}</span>
          </div>

          {status === "pending" && (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                className="text-green-400 border-green-400/30 hover:bg-green-400/10 hover:text-green-300 bg-transparent"
                onClick={() => onApprove(id)}
              >
                <Check className="w-4 h-4 mr-1" />
                Approve
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-red-400 border-red-400/30 hover:bg-red-400/10 hover:text-red-300 bg-transparent"
                onClick={() => onDecline(id)}
              >
                <X className="w-4 h-4 mr-1" />
                Decline
              </Button>
            </div>
          )}
        </div>
      </div>
    </Card>
  )
}
