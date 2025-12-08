"use client"

import { RoleCard } from "@/components/role-card"

interface Role {
  id: string
  name: string
  description: string
  permissions: string[]
  color: string
  userCount: number
}

interface AdminRolesClientProps {
  roles: Role[]
}

export function AdminRolesClient({ roles }: AdminRolesClientProps) {
  const handleEdit = (id: string) => {
    // Roles are predefined and cannot be edited
    alert("Roles are predefined and cannot be modified.")
  }

  const handleDelete = (id: string) => {
    // Roles are predefined and cannot be deleted
    alert("Roles are predefined and cannot be deleted.")
  }

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Role Management</h1>
          <p className="text-muted-foreground">View system roles and their permissions.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {roles.map((role) => (
          <RoleCard
            key={role.id}
            id={role.id}
            name={role.name}
            description={role.description}
            permissions={role.permissions}
            userCount={role.userCount}
            color={role.color}
            onEdit={handleEdit}
            onDelete={handleDelete}
          />
        ))}
      </div>
    </main>
  )
}
