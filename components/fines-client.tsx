"use client"

import { useState } from "react"
import { FineCard } from "@/components/fine-card"
import { FineFormModal } from "@/components/fine-form-modal"
import { DeleteConfirmModal } from "@/components/delete-confirm-modal"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Plus } from "lucide-react"
import { markFinePaid, deleteFine } from "@/lib/actions/fine-actions"
import type { FineWithDetails } from "@/lib/db"

interface FinesClientProps {
  initialFines: FineWithDetails[]
}

export function FinesClient({ initialFines }: FinesClientProps) {
  const [finesList, setFinesList] = useState(initialFines)
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [isEditModalOpen, setIsEditModalOpen] = useState(false)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [selectedFine, setSelectedFine] = useState<any>(null)

  const handleMarkPaid = async (id: string) => {
    const result = await markFinePaid(id)
    if (!result.error) {
      setFinesList(finesList.map((fine) => (fine.id === id ? { ...fine, status: "paid" as const } : fine)))
    }
  }

  const handleEdit = (id: string) => {
    const fine = finesList.find((f) => f.id === id)
    if (fine) {
      setSelectedFine({
        id: fine.id,
        studentName: fine.user?.full_name,
        bookTitle: fine.book?.title,
        fineType: fine.reason,
        amount: fine.amount,
        dateIssued: new Date(fine.created_at).toLocaleDateString(),
        status: fine.status,
      })
      setIsEditModalOpen(true)
    }
  }

  const handleDelete = (id: string) => {
    const fine = finesList.find((f) => f.id === id)
    if (fine) {
      setSelectedFine({
        id: fine.id,
        studentName: fine.user?.full_name,
      })
      setIsDeleteModalOpen(true)
    }
  }

  const handleAddSubmit = (data: any) => {
    // In a real app, you'd call createFine here
    window.location.reload()
  }

  const handleEditSubmit = (data: any) => {
    // In a real app, you'd call updateFine here
    window.location.reload()
  }

  const handleDeleteConfirm = async () => {
    if (selectedFine) {
      const result = await deleteFine(selectedFine.id)
      if (!result.error) {
        setFinesList(finesList.filter((fine) => fine.id !== selectedFine.id))
      }
      setIsDeleteModalOpen(false)
      setSelectedFine(null)
    }
  }

  const unpaidFines = finesList.filter((f) => f.status === "unpaid")
  const paidFines = finesList.filter((f) => f.status === "paid")
  const totalUnpaid = unpaidFines.reduce((sum, f) => sum + Number(f.amount), 0)

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Fines Management</h1>
          <p className="text-muted-foreground">
            Total unpaid fines:
<span className="text-red-400 font-semibold">
  ₱{totalUnpaid.toLocaleString("en-PH", { minimumFractionDigits: 2 })}
</span>

          </p>
        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add New Fine
        </Button>
      </div>

      <Tabs defaultValue="unpaid" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
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
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({finesList.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="unpaid">
          <div className="grid gap-4">
            {unpaidFines.length > 0 ? (
              unpaidFines.map((fine: any) => (
                <FineCard
                  key={fine.id}
                  id={fine.id}
                  studentName={fine.user?.full_name || "Unknown Student"}
                  bookTitle={fine.book?.title || "N/A"}
                  fineType={fine.reason === "overdue" ? "Overdue" : fine.reason === "damage" ? "Damaged" : "Lost"}
                  amount={Number(fine.amount)}
                  dateIssued={new Date(fine.created_at).toLocaleDateString()}
                  status="unpaid"
                  onMarkPaid={handleMarkPaid}
                  onEdit={handleEdit}
                  onDelete={handleDelete}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No unpaid fines</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="paid">
          <div className="grid gap-4">
            {paidFines.length > 0 ? (
              paidFines.map((fine: any) => (
                <FineCard
                  key={fine.id}
                  id={fine.id}
                  studentName={fine.user?.full_name || "Unknown Student"}
                  bookTitle={fine.book?.title || "N/A"}
                  fineType={fine.reason === "overdue" ? "Overdue" : fine.reason === "damage" ? "Damaged" : "Lost"}
                  amount={Number(fine.amount)}
                  dateIssued={new Date(fine.created_at).toLocaleDateString()}
                  status="paid"
                  onMarkPaid={handleMarkPaid}
                  onEdit={handleEdit}
                  onDelete={handleDelete}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No paid fines</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="all">
          <div className="grid gap-4">
            {finesList.map((fine: any) => (
              <FineCard
                key={fine.id}
                id={fine.id}
                studentName={fine.user?.full_name || "Unknown Student"}
                bookTitle={fine.book?.title || "N/A"}
                fineType={fine.reason === "overdue" ? "Overdue" : fine.reason === "damage" ? "Damaged" : "Lost"}
                amount={Number(fine.amount)}
                dateIssued={new Date(fine.created_at).toLocaleDateString()}
                status={fine.status as "paid" | "unpaid"}
                onMarkPaid={handleMarkPaid}
                onEdit={handleEdit}
                onDelete={handleDelete}
              />
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Add Fine Modal */}
      <FineFormModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
        mode="add"
      />

      {/* Edit Fine Modal */}
      <FineFormModal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false)
          setSelectedFine(null)
        }}
        onSubmit={handleEditSubmit}
        initialData={selectedFine}
        mode="edit"
      />

      {/* Delete Confirmation Modal */}
      <DeleteConfirmModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false)
          setSelectedFine(null)
        }}
        onConfirm={handleDeleteConfirm}
        title="Delete Fine"
        description={`Are you sure you want to delete this fine for ${selectedFine?.studentName}? This action cannot be undone.`}
      />
    </main>
  )
}
