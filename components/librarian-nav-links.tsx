"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"

const navItems = [
  { href: "/librarian", label: "Home" },
  { href: "/librarian/books", label: "Books" },
  { href: "/librarian/borrow-requests", label: "Borrow Requests" },
  { href: "/librarian/borrowed", label: "Borrowed" },
  { href: "/librarian/reservations", label: "Reservations" },
  { href: "/librarian/fines", label: "Fines" },
]

export function LibrarianNavLinks() {
  const pathname = usePathname()

  return (
    <>
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
    </>
  )
}
