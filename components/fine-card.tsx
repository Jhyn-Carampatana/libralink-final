"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { DollarSign, Calendar, CheckCircle, AlertCircle, Pencil, Trash2 } from "lucide-react"

interface FineCardProps {
  id: string
  studentName: string
  bookTitle: string
  fineType: string
  amount: number
  dateIssued: string
  status: "paid" | "unpaid"
  onMarkPaid: (id: string) => void
  onEdit: (id: string) => void
  onDelete: (id: string) => void
}

export function FineCard({
  id,
  studentName,
  bookTitle,
  fineType,
  amount,
  dateIssued,
  status,
  onMarkPaid,
  onEdit,
  onDelete,
}: FineCardProps) {
  const fineTypeColors: Record<string, string> = {
    Overdue: "text-yellow-400 bg-yellow-400/10",
    Damaged: "text-orange-400 bg-orange-400/10",
    Lost: "text-red-400 bg-red-400/10",
  }

  return (
    <Card className="glass-card p-4 hover:border-accent/30 transition-all">
      <div className="flex items-start justify-between">
        <div className="flex gap-4">
          {/* Icon */}
          <div className={`p-3 rounded-xl ${status === "paid" ? "bg-green-400/10" : "bg-red-400/10"}`}>
  <span className={`text-2xl font-bold ${status === "paid" ? "text-green-400" : "text-red-400"}`}>
    ₱
  </span>
</div>


          {/* Content */}
          <div className="space-y-1">
            <h3 className="font-semibold text-foreground">{studentName}</h3>
            <p className="text-sm text-muted-foreground">
              Book: <span className="text-foreground">{bookTitle}</span>
            </p>
            <div className="flex items-center gap-3 text-xs">
              <span className={`px-2 py-0.5 rounded ${fineTypeColors[fineType] || "text-muted-foreground bg-muted"}`}>
                {fineType}
              </span>
              <div className="flex items-center gap-1 text-muted-foreground">
                <Calendar className="w-3 h-3" />
                <span>{dateIssued}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Amount & Status */}
        <div className="text-right">
          <p className="text-2xl font-bold text-foreground">
  ₱{amount.toLocaleString("en-PH", { minimumFractionDigits: 2 })}
</p>

          <div
            className={`flex items-center gap-1 justify-end mt-1 ${status === "paid" ? "text-green-400" : "text-red-400"}`}
          >
            {status === "paid" ? (
              <>
                <CheckCircle className="w-3.5 h-3.5" />
                <span className="text-xs font-medium">Paid</span>
              </>
            ) : (
              <>
                <AlertCircle className="w-3.5 h-3.5" />
                <span className="text-xs font-medium">Unpaid</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2 mt-4 pt-4 border-t border-border">
        {status === "unpaid" && (
          <Button
            size="sm"
            className="bg-green-500/20 text-green-400 hover:bg-green-500/30 border-0"
            onClick={() => onMarkPaid(id)}
          >
            <CheckCircle className="w-4 h-4 mr-1" />
            Mark as Paid
          </Button>
        )}
        <Button size="sm" variant="outline" onClick={() => onEdit(id)}>
          <Pencil className="w-4 h-4 mr-1" />
          Edit
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="text-red-400 border-red-400/30 hover:bg-red-400/10 bg-transparent"
          onClick={() => onDelete(id)}
        >
          <Trash2 className="w-4 h-4 mr-1" />
          Delete
        </Button>
      </div>
    </Card>
  )
}
