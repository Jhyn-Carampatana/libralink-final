"use client"

import { Card } from "@/components/ui/card"
import { Clock, ArrowRight } from "lucide-react"

interface AdminAction {
  action: string
  details: string
  timestamp: string
}

interface AdminActionsCardProps {
  actions: AdminAction[]
}

export function AdminActionsCard({ actions }: AdminActionsCardProps) {
  return (
    <Card className="glass-card p-6">
      <h3 className="text-lg font-semibold text-foreground mb-4">Recent Admin Actions</h3>
      <div className="space-y-4">
        {actions.map((action, index) => (
          <div
            key={index}
            className="flex items-start gap-3 p-3 rounded-lg bg-secondary/30 hover:bg-secondary/50 transition-colors"
          >
            <div className="p-2 rounded-lg bg-accent/20">
              <ArrowRight className="w-4 h-4 text-accent" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-medium text-foreground text-sm">{action.action}</p>
              <p className="text-sm text-muted-foreground truncate">{action.details}</p>
              <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                {action.timestamp}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}
