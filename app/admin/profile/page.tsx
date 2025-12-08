export const dynamic = "force-dynamic";
export const revalidate = 0;

import { AdminHeader } from "@/components/admin-header"
import { AdminProfileCard } from "@/components/admin-profile-card"
import { AdminActionsCard } from "@/components/admin-actions-card"
import { getSession } from "@/lib/auth"
import { getSystemLogs } from "@/lib/actions/log-actions"
import { redirect } from "next/navigation"

export default async function AdminProfilePage() {
  const { user } = await getSession()

  if (!user) {
    redirect("/login")
  }

  const logs = await getSystemLogs(user.id)

  const adminProfile = {
    name: user.full_name || "Admin User",
    email: user.email,
    role: "System Administrator",
    avatar: user.avatar_url || "", // Empty string instead of mock image
    joinDate: new Date(user.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }),
    lastLogin: user.last_login ? new Date(user.last_login).toLocaleString() : "N/A",
    userId: user.id,
  }

  const adminActions = logs.slice(0, 10).map((log) => ({
    action: log.action,
    details: log.entity_type ? `${log.entity_type}: ${log.entity_id?.slice(0, 8)}...` : "System action",
    timestamp: new Date(log.created_at).toLocaleString(),
  }))

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />

      <main className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-1">Admin Profile</h1>
          <p className="text-muted-foreground">Manage your account settings and view activity</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <AdminProfileCard {...adminProfile} />
          </div>
          <div className="lg:col-span-2">
            <AdminActionsCard actions={adminActions} />
          </div>
        </div>
      </main>
    </div>
  )
}
