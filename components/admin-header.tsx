"use client"

import Link from "next/link"
import { useRouter, usePathname } from "next/navigation"
import { Logo } from "./logo"
import { LogOut, User, ChevronDown } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { logoutAction } from "@/lib/actions/auth-actions"

const navItems = [
  { href: "/admin", label: "Dashboard" },
  { href: "/admin/users", label: "Users" },
  { href: "/admin/roles", label: "Roles" },
  { href: "/admin/books", label: "Books" },
  { href: "/admin/transactions", label: "Transactions" },
  { href: "/admin/reservations", label: "Reservations" },
  { href: "/admin/fines", label: "Fines" },
  { href: "/admin/logs", label: "Logs" },
]

interface AdminHeaderProps {
  user?: {
    full_name: string | null
    email: string
  }
}

export function AdminHeader({ user }: AdminHeaderProps) {
  const router = useRouter()
  const pathname = usePathname()

  const displayName = user?.full_name || "Admin"

  const handleLogout = async () => {
    await logoutAction()
    router.push("/login")
  }

  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Logo size="sm" />
          <span className="text-xs font-medium text-accent px-2 py-0.5 bg-accent/20 rounded-full">Admin</span>
        </div>

        <nav className="flex items-center gap-4">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`text-sm font-medium transition-colors ${
                pathname === item.href ? "text-accent" : "text-foreground hover:text-accent"
              }`}
            >
              {item.label}
            </Link>
          ))}

          <DropdownMenu>
            <DropdownMenuTrigger className="focus:outline-none">
              <div className="flex items-center gap-2 hover:opacity-80 transition-opacity">
                <Avatar className="w-8 h-8 bg-accent/20 border border-accent/30">
                  <AvatarFallback className="bg-accent/20 text-accent text-sm font-medium">
                    {displayName.substring(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm font-medium text-foreground">{displayName}</span>
                <ChevronDown className="w-4 h-4 text-muted-foreground" />
              </div>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={() => router.push("/admin/profile")}>
                <User className="mr-2 h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleLogout}>
                <LogOut className="mr-2 h-4 w-4" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </nav>
      </div>
    </header>
  )
}
