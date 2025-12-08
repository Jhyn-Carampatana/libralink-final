import { Card } from "@/components/ui/card"
import { Calendar, Clock, AlertCircle, FileText } from "lucide-react"

interface BorrowedBookCardProps {
  title: string
  author: string
  category: string
  coverUrl: string
  coverColor?: string
  borrowDate: string
  daysLeft: number
  isOverdue: boolean
}

export function BorrowedBookCard({
  title,
  author,
  category,
  coverUrl,
  coverColor,
  borrowDate,
  daysLeft,
  isOverdue,
}: BorrowedBookCardProps) {
  return (
    <Card className="bg-card border-border overflow-hidden">
      <div className="flex gap-4 p-4">
        {/* Book Cover */}
        <div
          className="w-24 h-36 rounded-lg overflow-hidden flex-shrink-0"
          style={{ backgroundColor: coverColor || "#1a1a2e" }}
        >
          <img src={coverUrl || "/placeholder.svg"} alt={title} className="w-full h-full object-cover" />
        </div>

        {/* Book Info */}
        <div className="flex-1 flex flex-col justify-between">
          <div>
            <h3 className="font-semibold text-foreground text-sm line-clamp-2">
              {title} - By {author}
            </h3>
            <p className="text-xs text-muted-foreground mt-1">{category}</p>
          </div>

          <div className="space-y-2 mt-4">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Calendar className="w-3.5 h-3.5" />
              <span>Borrowed on {borrowDate}</span>
            </div>

            {isOverdue ? (
              <div className="flex items-center gap-2 text-xs text-destructive">
                <AlertCircle className="w-3.5 h-3.5" />
                <span>Overdue Return</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3.5 h-3.5" />
                <span>{daysLeft} days left to due</span>
              </div>
            )}
          </div>
        </div>

        {/* Receipt Icon */}
        <button className="self-end text-muted-foreground hover:text-foreground transition-colors">
          <FileText className="w-5 h-5" />
        </button>
      </div>
    </Card>
  )
}
