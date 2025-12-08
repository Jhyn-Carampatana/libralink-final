"use client"

import { useState, useTransition } from "react"
import { AdminFineCard } from "@/components/admin-fine-card"
import { AdminFineFormModal } from "@/components/admin-fine-form-modal"
import { DeleteConfirmModal } from "@/components/delete-confirm-modal"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Plus, Search } from "lucide-react"
import { markFinePaid, deleteFine, createFine } from "@/lib/actions/fine-actions"
import type { FineWithDetails } from "@/lib/db"

interface User {
  id: string
  full_name: string
  email: string
}

interface AdminFinesClientProps {
  initialFines: FineWithDetails[]
  users: User[]
}

export function AdminFinesClient({ initialFines, users }: AdminFinesClientProps) {
  const [fines, setFines] = useState(initialFines)
  const [searchQuery, setSearchQuery] = useState("")
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [isEditModalOpen, setIsEditModalOpen] = useState(false)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [selectedFine, setSelectedFine] = useState<FineWithDetails | null>(null)
  const [isPending, startTransition] = useTransition()

  const handleMarkPaid = (id: string) => {
    startTransition(async () => {
      const { error } = await markFinePaid(id)
      if (!error) {
        setFines(fines.map((f) => (f.id === id ? { ...f, status: "paid" } : f)))
      }
    })
  }

  const handleEdit = (id: string) => {
    const fine = fines.find((f) => f.id === id)
    if (fine) {
      setSelectedFine(fine)
      setIsEditModalOpen(true)
    }
  }

  const handleDelete = (id: string) => {
    const fine = fines.find((f) => f.id === id)
    if (fine) {
      setSelectedFine(fine)
      setIsDeleteModalOpen(true)
    }
  }
const peso = (amount: number) =>
  `₱${amount.toLocaleString("en-PH", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

  const handleAddSubmit = async (data: any) => {
    startTransition(async () => {
      const { fine, error } = await createFine({
        user_id: data.userId,
        amount: Number.parseFloat(data.amount),
        reason: data.reason || "other",
        description: data.description,
      })
      if (fine) {
        setIsAddModalOpen(false)
        window.location.reload()
      }
    })
  }

  const handleDeleteConfirm = async () => {
    if (!selectedFine) return
    startTransition(async () => {
      const { error } = await deleteFine(selectedFine.id)
      if (!error) {
        setFines(fines.filter((f) => f.id !== selectedFine.id))
        setIsDeleteModalOpen(false)
        setSelectedFine(null)
      }
    })
  }

  const mapToCardProps = (f: FineWithDetails) => ({
    id: f.id,
    studentName: (f.user as any)?.full_name || "Unknown User",
    studentAvatar: (f.user as any)?.avatar_url || "/placeholder.svg",
    bookTitle: (f.book as any)?.title || f.description || "N/A",
    amount: Number(f.amount),
    reason: f.reason,
    status: f.status as any,
      dateIssued: new Date(f.created_at).toLocaleDateString(),
})


  const filteredFines = fines.filter((f) => {
    const studentName = (f.user as any)?.full_name?.toLowerCase() || ""
    const bookTitle = (f.book as any)?.title?.toLowerCase() || ""
    return studentName.includes(searchQuery.toLowerCase()) || bookTitle.includes(searchQuery.toLowerCase())
  })

  const unpaidFines = filteredFines.filter((f) => f.status === "unpaid")
  const paidFines = filteredFines.filter((f) => f.status === "paid")
  const totalUnpaid = unpaidFines.reduce((sum, f) => sum + Number(f.amount), 0)

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Fine Management</h1>
          <p className="text-muted-foreground">
  Total unpaid fines:{" "}
  <span className="text-red-400 font-semibold">{peso(totalUnpaid)}</span>
</p>

        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
          disabled={isPending}
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Fine
        </Button>
      </div>

      <div className="relative mb-6 max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-5 h-5" />
        <Input
          placeholder="Search by student or book..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 bg-input border-border"
        />
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({filteredFines.length})
          </TabsTrigger>
          <TabsTrigger
            value="unpaid"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Unpaid ({unpaidFines.length})
          </TabsTrigger>
          <TabsTrigger
            value="paid"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Paid ({paidFines.length})
          </TabsTrigger>
        </TabsList>

        {[
          { value: "all", data: filteredFines },
          { value: "unpaid", data: unpaidFines },
          { value: "paid", data: paidFines },
        ].map(({ value, data }) => (
          <TabsContent key={value} value={value}>
            <div className="grid gap-4">
              {data.length > 0 ? (
                data.map((f) => (
                  <AdminFineCard
                    key={f.id}
                    {...mapToCardProps(f)}
                    onMarkPaid={handleMarkPaid}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                  />
                ))
              ) : (
                <div className="text-center py-16 glass-card rounded-2xl">
                  <p className="text-muted-foreground">No fines found</p>
                </div>
              )}
            </div>
          </TabsContent>
        ))}
      </Tabs>

      <AdminFineFormModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
        mode="add"
        users={users}
      />
      <AdminFineFormModal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false)
          setSelectedFine(null)
        }}
        onSubmit={() => {}}
        initialData={selectedFine ? mapToCardProps(selectedFine) : undefined}
        mode="edit"
        users={users}
      />
      <DeleteConfirmModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false)
          setSelectedFine(null)
        }}
        onConfirm={handleDeleteConfirm}
        title="Delete Fine"
        description={`Are you sure you want to delete this fine? This action cannot be undone.`}
      />
    </main>
  )
}
