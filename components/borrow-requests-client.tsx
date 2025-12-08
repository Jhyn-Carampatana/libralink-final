"use client"

import { useState } from "react"
import { BorrowRequestCard } from "@/components/borrow-request-card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { CheckCircle } from "lucide-react"
import { approveBorrowRequest, declineBorrowRequest } from "@/lib/actions/borrow-actions"
import type { BorrowRequestWithDetails } from "@/lib/db"

interface BorrowRequestsClientProps {
  initialRequests: BorrowRequestWithDetails[]
}

export function BorrowRequestsClient({ initialRequests }: BorrowRequestsClientProps) {
  const [requests, setRequests] = useState(initialRequests)
  const [successModal, setSuccessModal] = useState<{ open: boolean; message: string }>({ open: false, message: "" })
  const [isLoading, setIsLoading] = useState(false)

  const handleApprove = async (id: string) => {
    setIsLoading(true)
    const dueDate = new Date()
    dueDate.setDate(dueDate.getDate() + 14) // 14 days loan period

    const result = await approveBorrowRequest(id, dueDate)
    if (!result.error) {
      setRequests(requests.map((req) => (req.id === id ? { ...req, status: "approved" as const } : req)))
      setSuccessModal({
        open: true,
        message: "Borrow request approved successfully! The book has been issued to the student.",
      })
    }
    setIsLoading(false)
  }

  const handleDecline = async (id: string) => {
    setIsLoading(true)
    const result = await declineBorrowRequest(id)
    if (!result.error) {
      setRequests(requests.map((req) => (req.id === id ? { ...req, status: "declined" as const } : req)))
    }
    setIsLoading(false)
  }

  const pendingRequests = requests.filter((r) => r.status === "pending")
  const approvedRequests = requests.filter((r) => r.status === "approved")
  const declinedRequests = requests.filter((r) => r.status === "declined")

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">Borrow Requests</h1>
        <p className="text-muted-foreground">Manage book borrow requests from students</p>
      </div>

      <Tabs defaultValue="pending" className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger
            value="pending"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Pending ({pendingRequests.length})
          </TabsTrigger>
          <TabsTrigger
            value="approved"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Approved ({approvedRequests.length})
          </TabsTrigger>
          <TabsTrigger
            value="declined"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Declined ({declinedRequests.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="pending">
          <div className="grid gap-4">
            {pendingRequests.length > 0 ? (
              pendingRequests.map((request: any) => (
                <BorrowRequestCard
                  key={request.id}
                  id={request.id}
                  bookTitle={request.book?.title || "Unknown Book"}
                  bookCover={request.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={request.user?.full_name || "Unknown Student"}
                  studentEmail={request.user?.email || ""}
                  requestDate={new Date(request.requested_at).toLocaleDateString()}
                  status="pending"
                  onApprove={handleApprove}
                  onDecline={handleDecline}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No pending requests</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="approved">
          <div className="grid gap-4">
            {approvedRequests.length > 0 ? (
              approvedRequests.map((request: any) => (
                <BorrowRequestCard
                  key={request.id}
                  id={request.id}
                  bookTitle={request.book?.title || "Unknown Book"}
                  bookCover={request.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={request.user?.full_name || "Unknown Student"}
                  studentEmail={request.user?.email || ""}
                  requestDate={new Date(request.requested_at).toLocaleDateString()}
                  status="approved"
                  onApprove={handleApprove}
                  onDecline={handleDecline}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No approved requests</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="declined">
          <div className="grid gap-4">
            {declinedRequests.length > 0 ? (
              declinedRequests.map((request: any) => (
                <BorrowRequestCard
                  key={request.id}
                  id={request.id}
                  bookTitle={request.book?.title || "Unknown Book"}
                  bookCover={request.book?.cover_url || "/abstract-book-cover.png"}
                  studentName={request.user?.full_name || "Unknown Student"}
                  studentEmail={request.user?.email || ""}
                  requestDate={new Date(request.requested_at).toLocaleDateString()}
                  status="declined"
                  onApprove={handleApprove}
                  onDecline={handleDecline}
                />
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No declined requests</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* Success Modal */}
      <Dialog open={successModal.open} onOpenChange={(open) => setSuccessModal({ ...successModal, open })}>
        <DialogContent className="glass-card border-border max-w-md">
          <DialogHeader>
            <div className="flex flex-col items-center text-center gap-4">
              <div className="p-4 rounded-full bg-green-400/10">
                <CheckCircle className="w-10 h-10 text-green-400" />
              </div>
              <DialogTitle className="text-xl font-semibold text-foreground">Success!</DialogTitle>
              <DialogDescription className="text-muted-foreground">{successModal.message}</DialogDescription>
            </div>
          </DialogHeader>
          <Button
            onClick={() => setSuccessModal({ open: false, message: "" })}
            className="w-full mt-4 bg-primary text-primary-foreground"
          >
            Close
          </Button>
        </DialogContent>
      </Dialog>
    </main>
  )
}
