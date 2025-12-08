"use client"

import Link from "next/link"
import { User } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { LogoutButton } from "./logout-button"

interface HeaderClientProps {
  user: {
    id: string
    full_name: string
    email: string
  } | null
}

export function HeaderClient({ user }: HeaderClientProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="focus:outline-none">
        <div className="flex items-center gap-2 hover:opacity-80 transition-opacity">
          <Avatar className="w-8 h-8 bg-secondary border border-border">
            <AvatarFallback className="bg-secondary text-foreground text-sm font-medium">
              {user?.full_name?.substring(0, 2).toUpperCase() || "U"}
            </AvatarFallback>
          </Avatar>
          <span className="text-sm font-medium text-foreground">{user?.full_name || "Guest"}</span>
        </div>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuItem asChild>
          <Link href="/profile" className="flex items-center cursor-pointer">
            <User className="mr-2 h-4 w-4" />
            Profile
          </Link>
        </DropdownMenuItem>
        <LogoutButton />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
