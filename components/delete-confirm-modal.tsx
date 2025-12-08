"use client"

import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { AlertTriangle } from "lucide-react"

interface DeleteConfirmModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  description: string
}

export function DeleteConfirmModal({ isOpen, onClose, onConfirm, title, description }: DeleteConfirmModalProps) {
  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="p-3 rounded-full bg-destructive/10">
              <AlertTriangle className="w-6 h-6 text-destructive" />
            </div>
            <DialogTitle className="text-xl font-semibold text-foreground">{title}</DialogTitle>
          </div>
          <DialogDescription className="text-muted-foreground mt-2">{description}</DialogDescription>
        </DialogHeader>

        <div className="flex gap-3 mt-6">
          <Button variant="outline" onClick={onClose} className="flex-1 bg-transparent">
            Cancel
          </Button>
          <Button variant="destructive" onClick={onConfirm} className="flex-1">
            Delete
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
