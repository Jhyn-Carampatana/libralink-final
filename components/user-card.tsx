"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { MoreVertical, UserCog, UserX, UserCheck, Trash2 } from "lucide-react"

interface UserCardProps {
  id: string
  name: string
  email: string
  role: string
  status: string
  dateRegistered: string
  onChangeRole: (id: string) => void
  onToggleStatus: (id: string) => void
  onDelete: (id: string) => void
}

export function UserCard({
  id,
  name,
  email,
  role,
  status,
  dateRegistered,
  onChangeRole,
  onToggleStatus,
  onDelete,
}: UserCardProps) {
  const getStatusColor = () => {
    switch (status) {
      case "active":
        return "bg-green-500/20 text-green-400"
      case "inactive":
        return "bg-gray-500/20 text-gray-400"
      case "suspended":
        return "bg-red-500/20 text-red-400"
      default:
        return "bg-gray-500/20 text-gray-400"
    }
  }

  const getRoleColor = () => {
    switch (role) {
      case "Admin":
        return "bg-accent/20 text-accent"
      case "Librarian":
        return "bg-cyan-500/20 text-cyan-400"
      case "Faculty":
        return "bg-purple-500/20 text-purple-400"
      case "Student":
        return "bg-blue-500/20 text-blue-400"
      default:
        return "bg-gray-500/20 text-gray-400"
    }
  }

  return (
    <Card className="glass-card p-4 hover:border-accent/50 transition-all duration-300">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Avatar className="w-12 h-12 bg-secondary border border-border">
            <AvatarFallback className="bg-secondary text-foreground font-medium">
              {name.substring(0, 2).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div>
            <h3 className="font-semibold text-foreground">{name}</h3>
            <p className="text-sm text-muted-foreground">{email}</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getRoleColor()}`}>{role}</span>
          <span className={`px-3 py-1 rounded-full text-xs font-medium capitalize ${getStatusColor()}`}>{status}</span>
          <p className="text-sm text-muted-foreground hidden md:block">{dateRegistered}</p>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreVertical className="w-4 h-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => onChangeRole(id)}>
                <UserCog className="mr-2 h-4 w-4" />
                Change Role
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onToggleStatus(id)}>
                {status === "active" ? (
                  <>
                    <UserX className="mr-2 h-4 w-4" />
                    Deactivate
                  </>
                ) : (
                  <>
                    <UserCheck className="mr-2 h-4 w-4" />
                    Activate
                  </>
                )}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onDelete(id)} className="text-destructive">
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </Card>
  )
}
