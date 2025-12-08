export const dynamic = "force-dynamic";
export const revalidate = 0;

import { LibrarianHeader } from "@/components/librarian-header"
import { StatCard } from "@/components/stat-card"
import { getLibraryStats } from "@/lib/actions/stats-actions"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { BookOpen, BookCheck, AlertTriangle, Clock, DollarSign } from "lucide-react"
import Link from "next/link"

export default async function LibrarianDashboard() {
  const { user } = await getSession()

  if (!user || (user.role !== "librarian" && user.role !== "admin")) {
    redirect("/login")
  }

  const stats = await getLibraryStats()

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />

      {/* FIXED CENTERED WRAPPER */}
      <main className="w-full flex justify-center px-4 py-8">
        <div className="w-full max-w-7xl">

          {/* Hero Section */}
          <div className="mb-10">
            <h1 className="text-4xl font-bold text-foreground mb-2">
              Welcome, {user.full_name}
            </h1>
            <p className="text-muted-foreground text-lg">
              Manage books, users, borrow requests, and library operations efficiently.
            </p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-10">
            <Link href="/librarian/books">
              <StatCard title="Total Books" value={stats.totalBooks} icon={BookOpen} iconColor="text-blue-400" />
            </Link>
            <Link href="/librarian/borrowed">
              <StatCard title="Books Borrowed" value={stats.booksBorrowed} icon={BookCheck} iconColor="text-green-400" />
            </Link>
            <Link href="/librarian/borrowed">
              <StatCard title="Overdue Books" value={stats.overdueBooks} icon={AlertTriangle} iconColor="text-red-400" />
            </Link>
            <Link href="/librarian/reservations">
              <StatCard title="Active Reservations" value={stats.activeReservations} icon={Clock} iconColor="text-yellow-400" />
            </Link>
            <Link href="/librarian/fines">
              <StatCard
              title="Unpaid Fines"
              value={`₱${stats.unpaidFines.toFixed(2)}`}
              icon={() => <span className="text-3xl text-orange-400 font-bold">₱</span>}
              iconColor=""
            />

            </Link>
          </div>

          {/* Quick Actions */}
          <div className="glass-card rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-foreground mb-4">Quick Actions</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

              <Link
                href="/librarian/books?action=add"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <BookOpen className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Add New Book</span>
              </Link>

              <Link
                href="/librarian/borrow-requests"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <BookCheck className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Process Requests</span>
              </Link>

              <Link
                href="/librarian/reservations"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <Clock className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Manage Reservations</span>
              </Link>

              <Link
                href="/librarian/fines"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <span className="text-3xl text-accent mb-2 group-hover:scale-110 transition-transform font-bold">
  ₱
</span>

                <span className="text-sm font-medium text-foreground">Manage Fines</span>
              </Link>

            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
