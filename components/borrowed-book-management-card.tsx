"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Calendar, Clock, AlertTriangle, RotateCcw } from "lucide-react"

interface BorrowedBookManagementCardProps {
  id: string
  bookTitle: string
  bookCover: string
  borrowedBy: string
  borrowDate: string
  dueDate: string
  daysRemaining: number
  isOverdue: boolean
  onReturn: (id: string) => void
}

export function BorrowedBookManagementCard({
  id,
  bookTitle,
  bookCover,
  borrowedBy,
  borrowDate,
  dueDate,
  daysRemaining,
  isOverdue,
  onReturn,
}: BorrowedBookManagementCardProps) {
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
            Borrowed by: <span className="text-foreground">{borrowedBy}</span>
          </p>

          <div className="flex flex-wrap gap-4 mt-2 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5" />
              <span>Borrowed: {borrowDate}</span>
            </div>
            <div className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              <span>Due: {dueDate}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between mt-3">
          {isOverdue ? (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-red-400/10">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
              <span className="text-xs font-medium text-red-400">Overdue by {Math.abs(daysRemaining)} days</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-green-400/10">
              <Clock className="w-3.5 h-3.5 text-green-400" />
              <span className="text-xs font-medium text-green-400">{daysRemaining} days remaining</span>
            </div>
          )}

          <Button
            size="sm"
            className="bg-primary text-primary-foreground hover:bg-primary/90"
            onClick={() => onReturn(id)}
          >
            <RotateCcw className="w-4 h-4 mr-1" />
            Mark as Returned
          </Button>
        </div>
      </div>
    </Card>
  )
}
