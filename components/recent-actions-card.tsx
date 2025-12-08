import type React from "react"
import { Card } from "@/components/ui/card"
import { BookPlus, CheckCircle, DollarSign, RotateCcw, XCircle } from "lucide-react"

interface Action {
  action: string
  details: string
  timestamp: string
}

interface RecentActionsCardProps {
  actions?: Action[]
}

const actionIcons: { [key: string]: React.ReactNode } = {
  borrow_approved: <CheckCircle className="w-4 h-4 text-green-400" />,
  book_added: <BookPlus className="w-4 h-4 text-blue-400" />,
  fine_created: <DollarSign className="w-4 h-4 text-orange-400" />,
  fine_paid: <DollarSign className="w-4 h-4 text-green-400" />,
  book_returned: <RotateCcw className="w-4 h-4 text-accent" />,
  borrow_declined: <XCircle className="w-4 h-4 text-red-400" />,
}

export function RecentActionsCard({ actions = [] }: RecentActionsCardProps) {
  return (
    <Card className="bg-card border-border overflow-hidden">
      <div className="p-6">
        <h3 className="text-lg font-semibold text-foreground mb-4">Recent Actions</h3>
        <div className="space-y-4">
          {actions.length > 0 ? (
            actions.map((action, index) => (
              <div key={index} className="flex items-start gap-3 pb-4 border-b border-border last:border-0 last:pb-0">
                <div className="p-2 rounded-lg bg-secondary/50">
                  {actionIcons[action.action] || <CheckCircle className="w-4 h-4 text-muted-foreground" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">{action.action.replace(/_/g, " ")}</p>
                  <p className="text-xs text-muted-foreground truncate">{action.details}</p>
                </div>
                <span className="text-xs text-muted-foreground whitespace-nowrap">{action.timestamp}</span>
              </div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">No recent actions</p>
          )}
        </div>
      </div>
    </Card>
  )
}
