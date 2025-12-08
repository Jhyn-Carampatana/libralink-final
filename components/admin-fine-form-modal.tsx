"use client"

import type React from "react"
import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

interface User {
  id: string
  full_name: string
  email: string
}

interface AdminFineFormModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  initialData?: any
  mode: "add" | "edit"
  users?: User[]
}

export function AdminFineFormModal({
  isOpen,
  onClose,
  onSubmit,
  initialData,
  mode,
  users = [],
}: AdminFineFormModalProps) {
  const [formData, setFormData] = useState({
    userId: "",
    bookTitle: "",
    reason: "Overdue",
    amount: 0,
    description: "",
  })

  useEffect(() => {
    if (initialData) {
      setFormData({
        userId: initialData.userId || "",
        bookTitle: initialData.bookTitle || "",
        reason: initialData.reason || "Overdue",
        amount: initialData.amount || 0,
        description: initialData.description || "",
      })
    } else {
      setFormData({
        userId: "",
        bookTitle: "",
        reason: "Overdue",
        amount: 0,
        description: "",
      })
    }
  }, [initialData, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    onSubmit({
      userId: formData.userId,
      amount: formData.amount,
      reason: formData.reason.toLowerCase(),
      description: formData.description || formData.bookTitle,
    })

    onClose()
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-foreground">
            {mode === "add" ? "Add New Fine" : "Edit Fine"}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* STUDENT */}
          <div className="space-y-2">
            <Label htmlFor="userId" className="text-foreground">Student</Label>

            <Select
              value={formData.userId}
              onValueChange={(value) => setFormData({ ...formData, userId: value })}
            >
              <SelectTrigger className="bg-input border-border">
                <SelectValue placeholder="Select a student" />
              </SelectTrigger>

              <SelectContent>
                {users.map((user) => (
                  <SelectItem key={user.id} value={user.id}>
                    {user.full_name} ({user.email})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* DESCRIPTION */}
          <div className="space-y-2">
            <Label htmlFor="description" className="text-foreground">
              Description (Optional — e.g., Book Title)
            </Label>

            <Input
              id="description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Enter description or book title"
              className="bg-input border-border"
            />
          </div>

          {/* REASON */}
          <div className="space-y-2">
            <Label htmlFor="reason" className="text-foreground">Reason</Label>

            <Select
              value={formData.reason}
              onValueChange={(value) => setFormData({ ...formData, reason: value })}
            >
              <SelectTrigger className="bg-input border-border">
                <SelectValue placeholder="Select reason" />
              </SelectTrigger>

              <SelectContent>
                <SelectItem value="Overdue">Overdue</SelectItem>
                <SelectItem value="Damaged">Damaged</SelectItem>
                <SelectItem value="Lost">Lost</SelectItem>
                <SelectItem value="Other">Other</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* AMOUNT — PESO FIX */}
          <div className="space-y-2">
            <Label htmlFor="amount" className="text-foreground">Amount (₱)</Label>

            <Input
              id="amount"
              type="number"
              step="0.01"
              min="0"
              value={formData.amount}
              onChange={(e) =>
                setFormData({ ...formData, amount: Number.parseFloat(e.target.value) || 0 })
              }
              placeholder="Enter amount"
              className="bg-input border-border"
              required
            />
          </div>

          {/* BUTTONS */}
          <div className="flex justify-end gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>

            <Button
              type="submit"
              className="bg-primary text-primary-foreground hover:bg-primary/90"
              disabled={!formData.userId}
            >
              {mode === "add" ? "Add Fine" : "Save Changes"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
