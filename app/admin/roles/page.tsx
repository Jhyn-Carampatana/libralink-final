export const dynamic = "force-dynamic";
export const revalidate = 0;

import { getUserStats } from "@/lib/actions/user-actions"
import { AdminHeader } from "@/components/admin-header"
import { RolesClient } from "@/components/roles-client"

const predefinedRoles = [
  {
    id: "admin",
    name: "Admin",
    description: "Full system access with user management capabilities",
    permissions: ["Manage Users", "Manage Books", "Manage Fines", "View Logs", "System Settings"],
    color: "bg-red-500/20 text-red-400",
  },
  {
    id: "librarian",
    name: "Librarian",
    description: "Manage books, borrow requests, and fines",
    permissions: ["Manage Books", "Approve Borrows", "Issue Fines", "Manage Reservations"],
    color: "bg-blue-500/20 text-blue-400",
  },
  {
    id: "faculty",
    name: "Faculty",
    description: "Extended borrowing privileges for faculty members",
    permissions: ["Borrow Books", "Reserve Books", "Extended Loan Period"],
    color: "bg-green-500/20 text-green-400",
  },
  {
    id: "student",
    name: "Student",
    description: "Standard library access for students",
    permissions: ["Borrow Books", "Reserve Books", "View Catalog"],
    color: "bg-yellow-500/20 text-yellow-400",
  },
]

export default async function RolesPage() {
  const stats = await getUserStats()

  const rolesWithCounts = predefinedRoles.map((role) => ({
    ...role,
    userCount:
      Number(
        stats[
          role.id === "admin"
            ? "admins"
            : role.id === "librarian"
              ? "librarians"
              : role.id === "faculty"
                ? "faculty"
                : "students"
        ],
      ) || 0,
  }))

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <RolesClient initialRoles={rolesWithCounts} />
    </div>
  )
}
