export const dynamic = "force-dynamic";
export const revalidate = 0;


import { AdminHeader } from "@/components/admin-header"
import { getFines } from "@/lib/actions/fine-actions"
import { getUsers } from "@/lib/actions/user-actions"
import { AdminFinesClient } from "@/components/admin-fines-client"

export default async function AdminFinesPage() {
  const [fines, users] = await Promise.all([getFines(), getUsers()])

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <AdminFinesClient initialFines={fines} users={users} />
    </div>
  )
}
