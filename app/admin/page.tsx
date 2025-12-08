export const dynamic = "force-dynamic";
export const revalidate = 0;

import { AdminHeader } from "@/components/admin-header"
import { StatCard } from "@/components/stat-card"
import { getAdminStats } from "@/lib/actions/stats-actions" 
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import {
  Users,
  BookOpen,
  BookCheck,
  AlertTriangle,
  Clock,
  DollarSign,
  Shield,
  UserCog,
} from "lucide-react"
import Link from "next/link"

export default async function AdminDashboard() {
  const { user } = await getSession()

  if (!user || user.role !== "admin") {
    redirect("/login")
  }

  const stats = await getAdminStats()

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader user={user} />

      {/* FIXED CENTER WRAPPER */}
      <main className="w-full flex justify-center px-4 py-8">
        <div className="w-full max-w-7xl">
          
          {/* Hero Section */}
          <div className="mb-10">
            <h1 className="text-4xl font-bold text-foreground mb-2">
              Welcome, {user.full_name} — System Overview
            </h1>
            <p className="text-muted-foreground text-lg">
              Monitor and manage all aspects of the LibraLink library system.
            </p>
          </div>

          {/* USER STATISTICS */}
          <div className="glass-card rounded-2xl p-6 mb-8">
            <h2 className="text-xl font-semibold text-foreground mb-6 flex items-center gap-2">
              <Users className="w-5 h-5 text-accent" />
              User Statistics
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
              <Link href="/admin/users">
                <StatCard
                  title="Total Users"
                  value={stats.users.total}
                  icon={Users}
                  iconColor="text-blue-400"
                />
              </Link>

              <Link href="/admin/users?role=student">
                <StatCard
                  title="Students"
                  value={stats.users.students}
                  icon={Users}
                  iconColor="text-green-400"
                />
              </Link>

              <Link href="/admin/users?role=faculty">
                <StatCard
                  title="Faculty"
                  value={stats.users.faculty}
                  icon={UserCog}
                  iconColor="text-purple-400"
                />
              </Link>

              <Link href="/admin/users?role=librarian">
                <StatCard
                  title="Librarians"
                  value={stats.users.librarians}
                  icon={BookOpen}
                  iconColor="text-cyan-400"
                />
              </Link>

              <Link href="/admin/users?role=admin">
                <StatCard
                  title="Admins"
                  value={stats.users.admins}
                  icon={Shield}
                  iconColor="text-accent"
                />
              </Link>
            </div>
          </div>

          {/* LIBRARY STATISTICS */}
          <div className="glass-card rounded-2xl p-6 mb-8">
            <h2 className="text-xl font-semibold text-foreground mb-6 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-accent" />
              Library Statistics
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
              <Link href="/admin/books">
                <StatCard
                  title="Total Books"
                  value={stats.library.totalBooks}
                  icon={BookOpen}
                  iconColor="text-blue-400"
                />
              </Link>

              <Link href="/admin/transactions">
                <StatCard
                  title="Books Borrowed"
                  value={stats.library.booksBorrowed}
                  icon={BookCheck}
                  iconColor="text-green-400"
                />
              </Link>

              <Link href="/admin/transactions?status=overdue">
                <StatCard
                  title="Overdue Books"
                  value={stats.library.overdueBooks}
                  icon={AlertTriangle}
                  iconColor="text-red-400"
                />
              </Link>

              <Link href="/admin/reservations">
                <StatCard
                  title="Active Reservations"
                  value={stats.library.activeReservations}
                  icon={Clock}
                  iconColor="text-yellow-400"
                />
              </Link>

              <Link href="/admin/fines">
                <StatCard
    title="Unpaid Fines"
    value={`₱${stats.library.unpaidFines.toLocaleString("en-PH", { minimumFractionDigits: 2 })}`}
    icon={() => (
      <span className="text-3xl font-bold text-orange-400">₱</span>
    )}
    iconColor=""
  />
              </Link>
            </div>
          </div>

          {/* QUICK ACTIONS */}
          <div className="glass-card rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-foreground mb-4">Quick Actions</h2>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Link
                href="/admin/users?action=add"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <Users className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Add New User</span>
              </Link>

              <Link
                href="/admin/books?action=add"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <BookOpen className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Add New Book</span>
              </Link>

              <Link
                href="/admin/roles"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <Shield className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">Manage Roles</span>
              </Link>

              <Link
                href="/admin/logs"
                className="flex flex-col items-center justify-center p-6 rounded-xl bg-secondary/30 hover:bg-secondary/50 transition-colors group"
              >
                <Clock className="w-8 h-8 text-accent mb-2 group-hover:scale-110 transition-transform" />
                <span className="text-sm font-medium text-foreground">View Logs</span>
              </Link>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
