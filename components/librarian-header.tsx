import Link from "next/link"
import { Logo } from "./logo"
import { User } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { getSession } from "@/lib/auth"
import { LogoutButton } from "./logout-button"
import { LibrarianNavLinks } from "./librarian-nav-links"

export async function LibrarianHeader() {
  const { user } = await getSession()

  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Logo size="sm" />

        <nav className="flex items-center gap-6">
          <LibrarianNavLinks />

          <DropdownMenu>
            <DropdownMenuTrigger className="focus:outline-none">
              <div className="flex items-center gap-2 hover:opacity-80 transition-opacity">
                <Avatar className="w-8 h-8 bg-secondary border border-border">
                  <AvatarFallback className="bg-secondary text-foreground text-sm font-medium">
                    {user?.full_name?.substring(0, 2).toUpperCase() || "LB"}
                  </AvatarFallback>
                </Avatar>
                <span className="text-sm font-medium text-foreground">{user?.full_name || "Librarian"}</span>
              </div>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem asChild>
                <Link href="/librarian/profile" className="flex items-center cursor-pointer">
                  <User className="mr-2 h-4 w-4" />
                  Profile
                </Link>
              </DropdownMenuItem>
              <LogoutButton />
            </DropdownMenuContent>
          </DropdownMenu>
        </nav>
      </div>
    </header>
  )
}
