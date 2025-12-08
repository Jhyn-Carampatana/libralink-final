"use client"

import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function CategoryFormModal({
  isOpen,
  onClose,
  onSubmit,
  initialData,
  mode,
}: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: { name: string }) => void
  initialData?: { id: string; name: string } | null
  mode: "add" | "edit"
}) {
  const [name, setName] = useState("")

  useEffect(() => {
    setName(initialData?.name ?? "")
  }, [initialData, isOpen])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({ name })
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border max-w-md">
        <DialogHeader>
          <DialogTitle>{mode === "add" ? "Add Category" : "Edit Category"}</DialogTitle>
        </DialogHeader>

        <form onSubmit={submit} className="space-y-4 pt-2">
          <div>
            <Label>Name</Label>
            <Input
              placeholder="Enter category name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="flex gap-3">
            <Button type="button" variant="outline" className="flex-1" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" className="flex-1 bg-primary text-primary-foreground">
              {mode === "add" ? "Add" : "Save"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
