"use client"

import { useState } from "react"
import { BorrowedBookManagementCard } from "@/components/borrowed-book-management-card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { returnBook } from "@/lib/actions/borrow-actions"
import type { BorrowRequestWithDetails } from "@/lib/db"

interface BorrowedBooksClientProps {
  initialBooks: BorrowRequestWithDetails[]
}

export function BorrowedBooksClient({ initialBooks }: BorrowedBooksClientProps) {
  const [borrowedBooks, setBorrowedBooks] = useState(initialBooks)
  const [returnModal, setReturnModal] = useState<{ open: boolean; book: any; fineAmount: number }>({
    open: false,
    book: null,
    fineAmount: 0,
  })

  const handleReturn = (id: string) => {
    const book = borrowedBooks.find((b) => b.id === id)
    if (book) {
      const dueDate = new Date(book.due_date!)
      const now = new Date()
      const daysOverdue = Math.max(0, Math.ceil((now.getTime() - dueDate.getTime()) / (1000 * 60 * 60 * 24)))
      const fineAmount = daysOverdue * 0.5 // $0.50 per day

      setReturnModal({ open: true, book, fineAmount })
    }
  }

  const confirmReturn = async () => {
    if (returnModal.book) {
      const result = await returnBook(returnModal.book.id)
      if (!result.error) {
        setBorrowedBooks(borrowedBooks.filter((b) => b.id !== returnModal.book.id))
      }
      setReturnModal({ open: false, book: null, fineAmount: 0 })
    }
  }

  // Calculate active and overdue books
  const now = new Date()
  const activeBooks = borrowedBooks.filter((b) => new Date(b.due_date!) >= now)
  const overdueBooks = borrowedBooks.filter((b) => new Date(b.due_date!) < now)

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">Borrowed Books</h1>
        <p className="text-muted-foreground">Track and manage all borrowed books</p>
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({borrowedBooks.length})
          </TabsTrigger>
          <TabsTrigger
            value="active"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Active ({activeBooks.length})
          </TabsTrigger>
          <TabsTrigger
            value="overdue"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Overdue ({overdueBooks.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all">
          <div className="grid gap-4">
            {borrowedBooks.length > 0 ? (
              borrowedBooks.map((borrow: any) => {
                const dueDate = new Date(borrow.due_date)
                const daysRemaining = Math.ceil((dueDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

                return (
                  <BorrowedBookManagementCard
                    key={borrow.id}
                    id={borrow.id}
                    bookTitle={borrow.book?.title || "Unknown Book"}
                    bookCover={borrow.book?.cover_url || "/abstract-book-cover.png"}
                    borrowedBy={borrow.user?.full_name || "Unknown User"}
                    borrowDate={new Date(borrow.approved_at).toLocaleDateString()}
                    dueDate={dueDate.toLocaleDateString()}
                    daysRemaining={Math.abs(daysRemaining)}
                    isOverdue={daysRemaining < 0}
                    onReturn={handleReturn}
                  />
                )
              })
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No active borrows</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="active">
          <div className="grid gap-4">
            {activeBooks.length > 0 ? (
              activeBooks.map((borrow: any) => {
                const dueDate = new Date(borrow.due_date)
                const daysRemaining = Math.ceil((dueDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

                return (
                  <BorrowedBookManagementCard
                    key={borrow.id}
                    id={borrow.id}
                    bookTitle={borrow.book?.title || "Unknown Book"}
                    bookCover={borrow.book?.cover_url || "/abstract-book-cover.png"}
                    borrowedBy={borrow.user?.full_name || "Unknown User"}
                    borrowDate={new Date(borrow.approved_at).toLocaleDateString()}
                    dueDate={dueDate.toLocaleDateString()}
                    daysRemaining={daysRemaining}
                    isOverdue={false}
                    onReturn={handleReturn}
                  />
                )
              })
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No active borrows</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="overdue">
          <div className="grid gap-4">
            {overdueBooks.length > 0 ? (
              overdueBooks.map((borrow: any) => {
                const dueDate = new Date(borrow.due_date)
                const daysOverdue = Math.ceil((now.getTime() - dueDate.getTime()) / (1000 * 60 * 60 * 24))

                return (
                  <BorrowedBookManagementCard
                    key={borrow.id}
                    id={borrow.id}
                    bookTitle={borrow.book?.title || "Unknown Book"}
                    bookCover={borrow.book?.cover_url || "/abstract-book-cover.png"}
                    borrowedBy={borrow.user?.full_name || "Unknown User"}
                    borrowDate={new Date(borrow.approved_at).toLocaleDateString()}
                    dueDate={dueDate.toLocaleDateString()}
                    daysRemaining={daysOverdue}
                    isOverdue={true}
                    onReturn={handleReturn}
                  />
                )
              })
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No overdue books</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* Return Confirmation Modal */}
      {returnModal.open && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="glass-card p-6 rounded-2xl max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-foreground mb-2">Confirm Return</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Are you sure you want to mark "{returnModal.book?.book?.title}" as returned?
            </p>
            {returnModal.fineAmount > 0 && (
              <p className="text-sm text-destructive mb-4">
                This book is overdue. A fine of ${returnModal.fineAmount.toFixed(2)} will be applied.
              </p>
            )}
            <div className="flex gap-3">
              <button
                onClick={() => setReturnModal({ open: false, book: null, fineAmount: 0 })}
                className="flex-1 px-4 py-2 rounded-lg bg-secondary text-foreground hover:bg-secondary/80"
              >
                Cancel
              </button>
              <button
                onClick={confirmReturn}
                className="flex-1 px-4 py-2 rounded-lg bg-accent text-accent-foreground hover:bg-accent/90"
              >
                Confirm Return
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
