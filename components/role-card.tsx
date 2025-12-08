"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Users, Edit, Trash2, Shield } from "lucide-react"

interface RoleCardProps {
  id: string
  name: string
  description: string
  userCount: number
  permissions: string[]
  onEdit: (id: string) => void
  onDelete: (id: string) => void
}

export function RoleCard({ id, name, description, userCount, permissions, onEdit, onDelete }: RoleCardProps) {
  const getRoleIcon = () => {
    switch (name) {
      case "Admin":
        return "text-accent"
      case "Librarian":
        return "text-cyan-400"
      case "Faculty":
        return "text-purple-400"
      case "Student":
        return "text-blue-400"
      default:
        return "text-gray-400"
    }
  }

  return (
    <Card className="glass-card p-6 hover:border-accent/50 transition-all duration-300">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-xl bg-secondary/50 ${getRoleIcon()}`}>
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-xl font-semibold text-foreground">{name}</h3>
            <p className="text-sm text-muted-foreground">{description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="icon" onClick={() => onEdit(id)} className="h-8 w-8 hover:bg-secondary">
            <Edit className="w-4 h-4" />
          </Button>
          {name !== "Admin" && (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onDelete(id)}
              className="h-8 w-8 hover:bg-destructive/20 text-destructive"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 mb-4">
        <Users className="w-4 h-4 text-muted-foreground" />
        <span className="text-sm text-muted-foreground">
          {userCount} {userCount === 1 ? "user" : "users"}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        {permissions.slice(0, 4).map((permission) => (
          <span key={permission} className="px-2 py-1 bg-secondary/50 text-xs text-muted-foreground rounded-md">
            {permission.replace(/_/g, " ")}
          </span>
        ))}
        {permissions.length > 4 && (
          <span className="px-2 py-1 bg-secondary/50 text-xs text-accent rounded-md">
            +{permissions.length - 4} more
          </span>
        )}
      </div>
    </Card>
  )
}
