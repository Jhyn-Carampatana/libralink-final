"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { DollarSign, Calendar, Book, User, CheckCircle, Edit, Trash2 } from "lucide-react"

interface AdminFineCardProps {
  id: string
  studentName: string
  bookTitle: string
  reason: string
  amount: number
  dateIssued: string
  status: string
  onMarkPaid?: (id: string) => void
  onEdit?: (id: string) => void
  onDelete?: (id: string) => void
}

export function AdminFineCard({
  id,
  studentName,
  bookTitle,
  reason,
  amount,
  dateIssued,
  status,
  onMarkPaid,
  onEdit,
  onDelete,
}: AdminFineCardProps) {
  return (
    <Card className="glass-card p-4 hover:border-accent/50 transition-all duration-300">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-xl ${status === "paid" ? "bg-green-400/10" : "bg-red-400/10"}`}>
  <span className={`text-2xl font-bold ${status === "paid" ? "text-green-400" : "text-red-400"}`}>
    ₱
  </span>
</div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <span
                className={`px-2 py-0.5 rounded text-xs font-medium ${
                  status === "paid" ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"
                }`}
              >
                {status === "paid" ? "Paid" : "Unpaid"}
              </span>

              <span className="px-2 py-0.5 rounded text-xs font-medium bg-secondary text-muted-foreground">
                {reason}
              </span>
            </div>

            {/* PESO FIX */}
            <h3 className="font-semibold text-foreground">₱{amount.toFixed(2)}</h3>

            <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
              <span className="flex items-center gap-1">
                <User className="w-3 h-3" />
                {studentName}
              </span>

              <span className="flex items-center gap-1">
                <Book className="w-3 h-3" />
                {bookTitle}
              </span>

              <span className="flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                {dateIssued}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {status === "unpaid" && (
            <Button size="sm" onClick={() => onMarkPaid?.(id)} className="bg-green-600 hover:bg-green-700 text-white">
              <CheckCircle className="w-4 h-4 mr-1" />
              Mark Paid
            </Button>
          )}

          <Button variant="ghost" size="icon" onClick={() => onEdit?.(id)} className="h-8 w-8">
            <Edit className="w-4 h-4" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => onDelete?.(id)}
            className="h-8 w-8 text-destructive hover:bg-destructive/20"
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </Card>
  )
}
