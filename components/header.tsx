import Link from "next/link"
import { Logo } from "./logo"
import { getSession } from "@/lib/auth"
import { HeaderClient } from "./header-client"

export async function Header() {
  const { user } = await getSession()

  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Logo size="sm" />

        <nav className="flex items-center gap-6">
          <Link href="/dashboard" className="text-sm font-medium text-foreground hover:text-accent transition-colors">
            Home
          </Link>
          <Link href="/search" className="text-sm font-medium text-foreground hover:text-accent transition-colors">
            Search
          </Link>

          <HeaderClient user={user} />
        </nav>
      </div>
    </header>
  )
}
