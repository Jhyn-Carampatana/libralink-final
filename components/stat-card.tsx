import { Card } from "@/components/ui/card"
import type { LucideIcon } from "lucide-react"

interface StatCardProps {
  title: string
  value: number | string
  icon: LucideIcon
  href?: string
  iconColor?: string
}

export function StatCard({ title, value, icon: Icon, iconColor = "text-accent" }: StatCardProps) {
  return (
    <Card className="glass-card p-6 hover:border-accent/50 transition-all duration-300">
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-3xl font-bold text-foreground">{value}</p>
        </div>
        <div className={`p-3 rounded-xl bg-secondary/50 ${iconColor}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </Card>
  )
}
