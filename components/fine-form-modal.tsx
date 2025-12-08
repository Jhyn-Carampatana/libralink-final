"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

interface FineFormData {
  id?: string
  studentName: string
  bookTitle: string
  fineType: string
  amount: number
  dateIssued: string
  status: "paid" | "unpaid"
}

interface FineFormModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: FineFormData) => void
  initialData?: FineFormData | null
  mode: "add" | "edit"
}

const fineTypes = ["Overdue", "Damaged", "Lost"]

const defaultFormData: FineFormData = {
  studentName: "",
  bookTitle: "",
  fineType: "Overdue",
  amount: 0,
  dateIssued: new Date().toISOString().split("T")[0],
  status: "unpaid",
}

export function FineFormModal({ isOpen, onClose, onSubmit, initialData, mode }: FineFormModalProps) {
  const [formData, setFormData] = useState<FineFormData>(defaultFormData)

  useEffect(() => {
    if (initialData) {
      setFormData(initialData)
    } else {
      setFormData(defaultFormData)
    }
  }, [initialData, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
    onClose()
  }

  const handleChange = (field: keyof FineFormData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl font-semibold text-foreground">
            {mode === "add" ? "Add New Fine" : "Edit Fine"}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 mt-4">
          <div className="space-y-2">
            <Label htmlFor="studentName" className="text-sm text-muted-foreground">
              Student Name
            </Label>
            <Input
              id="studentName"
              value={formData.studentName}
              onChange={(e) => handleChange("studentName", e.target.value)}
              placeholder="Enter student name"
              required
              className="bg-input border-border"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="bookTitle" className="text-sm text-muted-foreground">
              Book Title
            </Label>
            <Input
              id="bookTitle"
              value={formData.bookTitle}
              onChange={(e) => handleChange("bookTitle", e.target.value)}
              placeholder="Enter book title"
              required
              className="bg-input border-border"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="fineType" className="text-sm text-muted-foreground">
                Fine Type
              </Label>
              <Select value={formData.fineType} onValueChange={(v) => handleChange("fineType", v)}>
                <SelectTrigger className="bg-input border-border">
                  <SelectValue placeholder="Select type" />
                </SelectTrigger>
                <SelectContent>
                  {fineTypes.map((type) => (
                    <SelectItem key={type} value={type}>
                      {type}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="amount" className="text-sm text-muted-foreground">
                Amount (₱)
              </Label>
              <Input
                id="amount"
                type="number"
                min={0}
                step={0.01}
                value={formData.amount}
                onChange={(e) => handleChange("amount", Number.parseFloat(e.target.value) || 0)}
                className="bg-input border-border"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="dateIssued" className="text-sm text-muted-foreground">
              Date Issued
            </Label>
            <Input
              id="dateIssued"
              type="date"
              value={formData.dateIssued}
              onChange={(e) => handleChange("dateIssued", e.target.value)}
              className="bg-input border-border"
            />
          </div>

          <div className="flex gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1 bg-transparent">
              Cancel
            </Button>
            <Button type="submit" className="flex-1 bg-primary text-primary-foreground hover:bg-primary/90">
              {mode === "add" ? "Add Fine" : "Save Changes"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
