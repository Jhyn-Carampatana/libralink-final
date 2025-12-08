export const dynamic = "force-dynamic";
export const revalidate = 0;


import { AdminHeader } from "@/components/admin-header"
import { AdminLogsClient } from "@/components/admin-logs-client"
import { getSystemLogs } from "@/lib/actions/log-actions"

export default async function SystemLogsPage() {
  const logs = await getSystemLogs()

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <AdminLogsClient initialLogs={logs} />
    </div>
  )
}
