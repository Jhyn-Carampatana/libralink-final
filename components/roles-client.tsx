"use client"

import { useState } from "react"
import { RoleCard } from "@/components/role-card"
import { RoleFormModal } from "@/components/role-form-modal"
import { DeleteConfirmModal } from "@/components/delete-confirm-modal"
import { Button } from "@/components/ui/button"

interface Role {
  id: string
  name: string
  description: string
  permissions: string[]
  color: string
  userCount: number
}

interface RolesClientProps {
  initialRoles: Role[]
}

export function RolesClient({ initialRoles }: RolesClientProps) {
  const [rolesList, setRolesList] = useState(initialRoles)
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [isEditModalOpen, setIsEditModalOpen] = useState(false)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)

  const handleEdit = (id: string) => {
    const role = rolesList.find((r) => r.id === id)
    if (role) {
      setSelectedRole(role)
      setIsEditModalOpen(true)
    }
  }

  const handleDelete = (id: string) => {
    const role = rolesList.find((r) => r.id === id)
    if (role) {
      setSelectedRole(role)
      setIsDeleteModalOpen(true)
    }
  }

  const handleAddSubmit = (data: any) => {
    const newRole = {
      ...data,
      id: Date.now().toString(),
      userCount: 0,
    }
    setRolesList([...rolesList, newRole])
  }

  const handleEditSubmit = (data: any) => {
    setRolesList(rolesList.map((role) => (role.id === data.id ? { ...role, ...data } : role)))
  }

  const handleDeleteConfirm = () => {
    if (selectedRole) {
      setRolesList(rolesList.filter((role) => role.id !== selectedRole.id))
      setIsDeleteModalOpen(false)
      setSelectedRole(null)
    }
  }

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Role Management</h1>
          <p className="text-muted-foreground">Configure roles and permissions for system users.</p>
        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
        >
          Add New Role
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {rolesList.map((role) => (
          <RoleCard key={role.id} {...role} onEdit={handleEdit} onDelete={handleDelete} />
        ))}
      </div>

      <RoleFormModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
        mode="add"
      />

      <RoleFormModal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false)
          setSelectedRole(null)
        }}
        onSubmit={handleEditSubmit}
        initialData={selectedRole}
        mode="edit"
      />

      <DeleteConfirmModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false)
          setSelectedRole(null)
        }}
        onConfirm={handleDeleteConfirm}
        title="Delete Role"
        description={`Are you sure you want to delete the "${selectedRole?.name}" role? All users with this role will need to be reassigned.`}
      />
    </main>
  )
}
