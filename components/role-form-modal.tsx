"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"

const availablePermissions = [
  { id: "borrow_books", label: "Borrow Books" },
  { id: "reserve_books", label: "Reserve Books" },
  { id: "view_catalog", label: "View Catalog" },
  { id: "extended_borrow", label: "Extended Borrow Period" },
  { id: "manage_books", label: "Manage Books" },
  { id: "process_requests", label: "Process Requests" },
  { id: "manage_fines", label: "Manage Fines" },
  { id: "view_reports", label: "View Reports" },
  { id: "manage_users", label: "Manage Users" },
  { id: "manage_roles", label: "Manage Roles" },
  { id: "system_settings", label: "System Settings" },
]

interface RoleFormModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  initialData?: any
  mode: "add" | "edit"
}

export function RoleFormModal({ isOpen, onClose, onSubmit, initialData, mode }: RoleFormModalProps) {
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    permissions: [] as string[],
  })

  useEffect(() => {
    if (initialData) {
      setFormData({
        name: initialData.name || "",
        description: initialData.description || "",
        permissions: initialData.permissions || [],
      })
    } else {
      setFormData({
        name: "",
        description: "",
        permissions: [],
      })
    }
  }, [initialData, isOpen])

  const handlePermissionToggle = (permissionId: string) => {
    setFormData((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(permissionId)
        ? prev.permissions.filter((p) => p !== permissionId)
        : [...prev.permissions, permissionId],
    }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      ...initialData,
      ...formData,
      userCount: initialData?.userCount || 0,
    })
    onClose()
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-foreground">{mode === "add" ? "Add New Role" : "Edit Role"}</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name" className="text-foreground">
              Role Name
            </Label>
            <Input
              id="name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="Enter role name"
              className="bg-input border-border"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="description" className="text-foreground">
              Description
            </Label>
            <Textarea
              id="description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Enter role description"
              className="bg-input border-border"
              rows={3}
            />
          </div>

          <div className="space-y-2">
            <Label className="text-foreground">Permissions</Label>
            <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto p-2 bg-secondary/30 rounded-lg">
              {availablePermissions.map((permission) => (
                <div key={permission.id} className="flex items-center gap-2">
                  <Checkbox
                    id={permission.id}
                    checked={formData.permissions.includes(permission.id)}
                    onCheckedChange={() => handlePermissionToggle(permission.id)}
                  />
                  <label htmlFor={permission.id} className="text-sm text-foreground cursor-pointer">
                    {permission.label}
                  </label>
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" className="bg-primary text-primary-foreground hover:bg-primary/90">
              {mode === "add" ? "Create Role" : "Save Changes"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
