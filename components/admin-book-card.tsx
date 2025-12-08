"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Pencil, Trash2 } from "lucide-react"

interface AdminBookCardProps {
  id: string
  title: string
  author: string
  category: string
  coverUrl: string
  coverColor?: string
  totalCopies: number
  availableCopies: number
  status?: string
  onEdit: (id: string) => void
  onDelete: (id: string) => void
}

export function AdminBookCard({
  id,
  title,
  author,
  category,
  coverUrl,
  coverColor,
  totalCopies,
  availableCopies,
  status = "Available",
  onEdit,
  onDelete,
}: AdminBookCardProps) {
  return (
    <Card className="group overflow-hidden bg-card border-border hover:border-accent/50 transition-all duration-300">
      <div className="aspect-[2/3] relative overflow-hidden" style={{ backgroundColor: coverColor || "#1a1a2e" }}>
        <img
          src={coverUrl || "/placeholder.svg"}
          alt={title}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
        />
        {/* Status Badge */}
        <div
          className={`absolute top-2 right-2 px-2 py-1 rounded-md text-xs font-medium ${
            status === "Available"
              ? "bg-green-500/80 text-white"
              : status === "Borrowed"
                ? "bg-yellow-500/80 text-black"
                : status === "Reserved"
                  ? "bg-blue-500/80 text-white"
                  : "bg-red-500/80 text-white"
          }`}
        >
          {status}
        </div>
      </div>
      <div className="p-4 space-y-3">
        <div className="space-y-1">
          <h3 className="font-semibold text-foreground text-sm line-clamp-1">{title}</h3>
          <p className="text-xs text-muted-foreground">By {author}</p>
          <p className="text-xs text-muted-foreground">{category}</p>
        </div>

        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">
            Copies:{" "}
            <span className="text-foreground font-medium">
              {availableCopies}/{totalCopies}
            </span>
          </span>
        </div>

        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="flex-1 text-xs bg-transparent" onClick={() => onEdit(id)}>
            <Pencil className="w-3 h-3 mr-1" />
            Edit
          </Button>
          <Button variant="destructive" size="sm" className="flex-1 text-xs" onClick={() => onDelete(id)}>
            <Trash2 className="w-3 h-3 mr-1" />
            Delete
          </Button>
        </div>
      </div>
    </Card>
  )
}
