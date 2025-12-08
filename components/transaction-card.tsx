"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import Image from "next/image"
import { Calendar, User, AlertTriangle, CheckCircle } from "lucide-react"

interface TransactionCardProps {
  id: string
  type: string
  bookTitle: string
  bookCover: string
  userName: string
  date: string
  dueDate: string | null
  status: string
  onMarkReturned?: (id: string) => void
  onMarkOverdue?: (id: string) => void
}

export function TransactionCard({
  id,
  type,
  bookTitle,
  bookCover,
  userName,
  date,
  dueDate,
  status,
  onMarkReturned,
  onMarkOverdue,
}: TransactionCardProps) {
  const getStatusColor = () => {
    switch (status) {
      case "active":
        return "bg-green-500/20 text-green-400"
      case "overdue":
        return "bg-red-500/20 text-red-400"
      case "completed":
        return "bg-blue-500/20 text-blue-400"
      default:
        return "bg-gray-500/20 text-gray-400"
    }
  }

  const getTypeColor = () => {
    switch (type) {
      case "borrow":
        return "bg-cyan-500/20 text-cyan-400"
      case "return":
        return "bg-green-500/20 text-green-400"
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
            <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${getTypeColor()}`}>{type}</span>
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
              {date}
            </span>
            {dueDate && <span className="flex items-center gap-1">Due: {dueDate}</span>}
          </div>
        </div>

        {status === "active" && type === "borrow" && (
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={() => onMarkReturned?.(id)}
              className="bg-green-600 hover:bg-green-700 text-white"
            >
              <CheckCircle className="w-4 h-4 mr-1" />
              Mark Returned
            </Button>
            <Button size="sm" variant="destructive" onClick={() => onMarkOverdue?.(id)}>
              <AlertTriangle className="w-4 h-4 mr-1" />
              Mark Overdue
            </Button>
          </div>
        )}
      </div>
    </Card>
  )
}
