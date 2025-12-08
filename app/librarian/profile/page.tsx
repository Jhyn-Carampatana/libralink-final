export const dynamic = "force-dynamic";
export const revalidate = 0;

import { LibrarianHeader } from "@/components/librarian-header"
import { AdminActionsCard } from "@/components/admin-actions-card"
import { getSession } from "@/lib/auth"
import { getSystemLogs } from "@/lib/actions/log-actions"
import { redirect } from "next/navigation"
import { AdminProfileCard } from "@/components/admin-profile-card"

export default async function LibrarianProfilePage() {
  const { user } = await getSession()

  if (!user) {
    redirect("/login")
  }

  // Get recent actions for this user
  const logs = await getSystemLogs(user.id)

  const librarianProfile = {
    name: user.full_name || "Librarian",
    email: user.email,
    role: "Librarian",
    avatar: user.avatar_url || "", // Empty string instead of mock image
    joinDate: new Date(user.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }),
    lastLogin: user.last_login ? new Date(user.last_login).toLocaleString() : "N/A",
    universityId: user.university_id || undefined,
    universityName: user.university_name || undefined,
    department: user.department || undefined,
    userId: user.id,
  }

  const recentActions = logs.slice(0, 10).map((log: any) => ({
    action: log.action,
    details: log.entity_type ? `${log.entity_type}: ${log.entity_id?.slice(0, 8)}...` : "System action",
    timestamp: new Date(log.created_at).toLocaleString(),
  }))

  return (
    <div className="min-h-screen gradient-bg">
      <LibrarianHeader />

      <main className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-1">Librarian Profile</h1>
          <p className="text-muted-foreground">Manage your account and view recent activity</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <AdminProfileCard {...librarianProfile} />
          </div>
          <div className="lg:col-span-2">
            <AdminActionsCard actions={recentActions} />
          </div>
        </div>
      </main>
    </div>
  )
}
