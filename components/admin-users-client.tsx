"use client"

import { useState, useTransition } from "react"
import { UserCard } from "@/components/user-card"
import { UserFormModal } from "@/components/user-form-modal"
import { DeleteConfirmModal } from "@/components/delete-confirm-modal"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Plus, Search } from "lucide-react"
import { createUser, updateUserRole, updateUserStatus, deleteUser } from "@/lib/actions/user-actions"
import type { User } from "@/lib/db"

interface AdminUsersClientProps {
  initialUsers: User[]
}

export function AdminUsersClient({ initialUsers }: AdminUsersClientProps) {
  const [users, setUsers] = useState(initialUsers)
  const [searchQuery, setSearchQuery] = useState("")
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isPending, startTransition] = useTransition()

  const handleChangeRole = (id: string) => {
    const user = users.find((u) => u.id === id)
    if (user) {
      setSelectedUser(user)
      setIsRoleModalOpen(true)
    }
  }

  const handleToggleStatus = (id: string) => {
    const user = users.find((u) => u.id === id)
    if (!user) return

    const newStatus = user.status === "active" ? "suspended" : "active"
    startTransition(async () => {
      const { error } = await updateUserStatus(id, newStatus as "active" | "suspended")
      if (!error) {
        setUsers(users.map((u) => (u.id === id ? { ...u, status: newStatus } : u)))
      }
    })
  }

  const handleDelete = (id: string) => {
    const user = users.find((u) => u.id === id)
    if (user) {
      setSelectedUser(user)
      setIsDeleteModalOpen(true)
    }
  }

  const handleAddSubmit = async (data: any) => {
    startTransition(async () => {
      const { user, error } = await createUser({
        email: data.email,
        password: data.password || "password123",
        full_name: data.name,
        role: data.role.toLowerCase(),
        university_id: data.universityId,
        university_name: data.university,
        year_level: data.yearLevel, // Added year_level
        course: data.course, // Added course
      })
      if (user) {
        setUsers([user, ...users])
        setIsAddModalOpen(false)
      }
    })
  }

  const handleRoleSubmit = async (data: any) => {
    if (!selectedUser) return
    startTransition(async () => {
      const { error } = await updateUserRole(selectedUser.id, data.role.toLowerCase())
      if (!error) {
        setUsers(users.map((u) => (u.id === selectedUser.id ? { ...u, role: data.role.toLowerCase() } : u)))
        setIsRoleModalOpen(false)
        setSelectedUser(null)
      }
    })
  }

  const handleDeleteConfirm = async () => {
    if (!selectedUser) return
    startTransition(async () => {
      const { error } = await deleteUser(selectedUser.id)
      if (!error) {
        setUsers(users.filter((u) => u.id !== selectedUser.id))
        setIsDeleteModalOpen(false)
        setSelectedUser(null)
      }
    })
  }

  const filteredUsers = users.filter(
    (user) =>
      user.full_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase()),
  )

  const studentUsers = filteredUsers.filter((u) => u.role === "student")
  const facultyUsers = filteredUsers.filter((u) => u.role === "faculty")
  const librarianUsers = filteredUsers.filter((u) => u.role === "librarian")
  const adminUsers = filteredUsers.filter((u) => u.role === "admin")

  const mapUserToCardProps = (user: User) => ({
    id: user.id,
    name: user.full_name || "Unknown",
    email: user.email,
    role: (user.role?.charAt(0).toUpperCase() + user.role?.slice(1)) as any,
    status: user.status as any,
    avatar: user.avatar_url || "/placeholder.svg",
    dateRegistered: new Date(user.created_at).toLocaleDateString(),
    universityId: user.university_id || "",
    yearLevel: user.year_level || "", // Added year_level
    course: user.course || "", // Added course
  })

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">User Management</h1>
          <p className="text-muted-foreground">Manage all system users, roles, and permissions.</p>
        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
          disabled={isPending}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add New User
        </Button>
      </div>

      <div className="relative mb-6">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-5 h-5" />
        <Input
          placeholder="Search users by name or email..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 bg-input border-border"
        />
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({filteredUsers.length})
          </TabsTrigger>
          <TabsTrigger
            value="students"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Students ({studentUsers.length})
          </TabsTrigger>
          <TabsTrigger
            value="faculty"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Faculty ({facultyUsers.length})
          </TabsTrigger>
          <TabsTrigger
            value="librarians"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Librarians ({librarianUsers.length})
          </TabsTrigger>
          <TabsTrigger
            value="admins"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Admins ({adminUsers.length})
          </TabsTrigger>
        </TabsList>

        {["all", "students", "faculty", "librarians", "admins"].map((tab) => {
          const tabUsers =
            tab === "all"
              ? filteredUsers
              : tab === "students"
                ? studentUsers
                : tab === "faculty"
                  ? facultyUsers
                  : tab === "librarians"
                    ? librarianUsers
                    : adminUsers

          return (
            <TabsContent key={tab} value={tab}>
              <div className="grid gap-4">
                {tabUsers.length > 0 ? (
                  tabUsers.map((user) => (
                    <UserCard
                      key={user.id}
                      {...mapUserToCardProps(user)}
                      onChangeRole={handleChangeRole}
                      onToggleStatus={handleToggleStatus}
                      onDelete={handleDelete}
                    />
                  ))
                ) : (
                  <div className="text-center py-16 glass-card rounded-2xl">
                    <p className="text-muted-foreground">No users found</p>
                  </div>
                )}
              </div>
            </TabsContent>
          )
        })}
      </Tabs>

      <UserFormModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
        mode="add"
      />
      <UserFormModal
        isOpen={isRoleModalOpen}
        onClose={() => {
          setIsRoleModalOpen(false)
          setSelectedUser(null)
        }}
        onSubmit={handleRoleSubmit}
        initialData={selectedUser ? mapUserToCardProps(selectedUser) : undefined}
        mode="role"
      />
      <DeleteConfirmModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false)
          setSelectedUser(null)
        }}
        onConfirm={handleDeleteConfirm}
        title="Delete User"
        description={`Are you sure you want to delete ${selectedUser?.full_name}? This action cannot be undone.`}
      />
    </main>
  )
}
