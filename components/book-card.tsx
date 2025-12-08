import Link from "next/link"
import { Card } from "@/components/ui/card"

interface BookCardProps {
  id: string
  title: string
  author: string
  category: string
  coverUrl?: string
}

export function BookCard({ id, title, author, category, coverUrl }: BookCardProps) {
  return (
    <Link href={`/book/${id}`}>
      <Card className="group overflow-hidden bg-card border-border hover:border-accent/50 transition-all duration-300 cursor-pointer">
        <div className="aspect-[2/3] relative overflow-hidden bg-muted/30">
          <img
            src={coverUrl || "/placeholder.svg?height=200&width=140&query=book cover"}
            alt={title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
        </div>
        <div className="p-4 space-y-1">
          <h3 className="font-semibold text-foreground text-sm line-clamp-1">
            {title} - By {author}
          </h3>
          <p className="text-xs text-muted-foreground">{category}</p>
        </div>
      </Card>
    </Link>
  )
}
