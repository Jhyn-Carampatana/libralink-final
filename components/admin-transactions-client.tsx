"use client"

import { useState, useTransition } from "react"
import { TransactionCard } from "@/components/transaction-card"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Search } from "lucide-react"
import { returnBook } from "@/lib/actions/borrow-actions"
import type { BorrowRequestWithDetails } from "@/lib/db"

interface AdminTransactionsClientProps {
  initialTransactions: BorrowRequestWithDetails[]
}

export function AdminTransactionsClient({ initialTransactions }: AdminTransactionsClientProps) {
  const [transactions, setTransactions] = useState(initialTransactions)
  const [searchQuery, setSearchQuery] = useState("")
  const [isPending, startTransition] = useTransition()

  const handleMarkReturned = (id: string) => {
    startTransition(async () => {
      const { error } = await returnBook(id)
      if (!error) {
        setTransactions(transactions.map((t) => (t.id === id ? { ...t, status: "returned" } : t)))
      }
    })
  }

  const handleMarkOverdue = (id: string) => {
    setTransactions(transactions.map((t) => (t.id === id ? { ...t, status: "overdue" } : t)))
  }

  // 🔥 FIXED: Matches TransactionCard exact props
  const mapToCardProps = (t: BorrowRequestWithDetails) => ({
    id: t.id,
    bookTitle: (t.book as any)?.title || "Unknown Book",
    bookCover: (t.book as any)?.cover_url || "/abstract-book-cover.png",
    userName: (t.user as any)?.full_name || "Unknown User",

    // TransactionCard expects "date"
    date: t.approved_at
      ? new Date(t.approved_at).toLocaleDateString()
      : new Date(t.requested_at).toLocaleDateString(),

    // TransactionCard expects "dueDate: string | null"
    dueDate: t.due_date ? new Date(t.due_date).toLocaleDateString() : null,

    // TransactionCard expects type: "borrow" | "return"
    type: t.status === "returned" ? "return" : "borrow",

    // TransactionCard expects a UI-friendly status
    status:
      t.status === "approved"
        ? "active"
        : t.status === "returned"
        ? "completed"
        : t.status,
  })

  const filteredTransactions = transactions.filter((t) => {
    const bookTitle = (t.book as any)?.title?.toLowerCase() || ""
    const userName = (t.user as any)?.full_name?.toLowerCase() || ""
    return bookTitle.includes(searchQuery.toLowerCase()) || userName.includes(searchQuery.toLowerCase())
  })

  const activeTransactions = filteredTransactions.filter((t) => t.status === "approved")
  const overdueTransactions = filteredTransactions.filter((t) => t.status === "overdue")
  const completedTransactions = filteredTransactions.filter((t) => t.status === "returned")

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">Borrow/Return Transactions</h1>
        <p className="text-muted-foreground">Monitor all book borrowing and return activities</p>
      </div>

      <div className="relative mb-6 max-w-md">
        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-5 h-5" />
        <Input
          placeholder="Search by book title or user..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 bg-input border-border"
        />
      </div>

      <Tabs defaultValue="all" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger value="all" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            All ({filteredTransactions.length})
          </TabsTrigger>
          <TabsTrigger value="active" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            Active ({activeTransactions.length})
          </TabsTrigger>
          <TabsTrigger value="overdue" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            Overdue ({overdueTransactions.length})
          </TabsTrigger>
          <TabsTrigger value="completed" className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground">
            Completed ({completedTransactions.length})
          </TabsTrigger>
        </TabsList>

        {[ 
          { value: "all", data: filteredTransactions },
          { value: "active", data: activeTransactions },
          { value: "overdue", data: overdueTransactions },
          { value: "completed", data: completedTransactions },
        ].map(({ value, data }) => (
          <TabsContent key={value} value={value}>
            <div className="grid gap-4">
              {data.length > 0 ? (
                data.map((t) => (
                  <TransactionCard
                    key={t.id}
                    {...mapToCardProps(t)}
                    onMarkReturned={handleMarkReturned}
                    onMarkOverdue={handleMarkOverdue}
                  />
                ))
              ) : (
                <div className="text-center py-16 glass-card rounded-2xl">
                  <p className="text-muted-foreground">No transactions found</p>
                </div>
              )}
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </main>
  )
}
