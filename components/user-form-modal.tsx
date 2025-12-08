"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

interface UserFormModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: any) => void
  initialData?: any
  mode: "add" | "edit" | "role"
}

export function UserFormModal({ isOpen, onClose, onSubmit, initialData, mode }: UserFormModalProps) {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    role: "Student",
    status: "active",
    password: "",
    studentId: "", // Added Student ID field
    yearLevel: "",
    course: "",
  })

  useEffect(() => {
    if (initialData) {
      setFormData({
        name: initialData.name || "",
        email: initialData.email || "",
        role: initialData.role || "Student",
        status: initialData.status || "active",
        password: "",
        studentId: initialData.studentId || "", // Added Student ID
        yearLevel: initialData.yearLevel || "",
        course: initialData.course || "",
      })
    } else {
      setFormData({
        name: "",
        email: "",
        role: "Student",
        status: "active",
        password: "",
        studentId: "",
        yearLevel: "",
        course: "",
      })
    }
  }, [initialData, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      ...initialData,
      ...formData,
      dateRegistered: initialData?.dateRegistered || new Date().toISOString().split("T")[0],
    })
    onClose()
  }

  const getTitle = () => {
    switch (mode) {
      case "add":
        return "Add New User"
      case "edit":
        return "Edit User"
      case "role":
        return "Change User Role"
      default:
        return "User"
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-foreground">{getTitle()}</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {mode !== "role" && (
            <>
              <div className="space-y-2">
                <Label htmlFor="name" className="text-foreground">
                  Full Name
                </Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="Enter full name"
                  className="bg-input border-border"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email" className="text-foreground">
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="Enter email"
                  className="bg-input border-border"
                  required
                />
              </div>
            </>
          )}

          {mode === "add" && (
            <div className="space-y-2">
              <Label htmlFor="password" className="text-foreground">
                Password
              </Label>
              <Input
                id="password"
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                placeholder="Enter password"
                className="bg-input border-border"
                required
              />
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="role" className="text-foreground">
              Role
            </Label>
            <Select value={formData.role} onValueChange={(value) => setFormData({ ...formData, role: value })}>
              <SelectTrigger className="bg-input border-border">
                <SelectValue placeholder="Select role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Student">Student</SelectItem>
                <SelectItem value="Faculty">Faculty</SelectItem>
                <SelectItem value="Librarian">Librarian</SelectItem>
                <SelectItem value="Admin">Admin</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {mode === "add" && (
            <>
              <div className="space-y-2">
                <Label htmlFor="studentId" className="text-foreground">
                  Student ID
                </Label>
                <Input
                  id="studentId"
                  value={formData.studentId}
                  onChange={(e) => setFormData({ ...formData, studentId: e.target.value })}
                  placeholder="e.g., 2024-00001"
                  className="bg-input border-border"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="yearLevel" className="text-foreground">
                  Year Level
                </Label>
                <Input
                  id="yearLevel"
                  value={formData.yearLevel}
                  onChange={(e) => setFormData({ ...formData, yearLevel: e.target.value })}
                  placeholder="e.g., 1st Year, 2nd Year"
                  className="bg-input border-border"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="course" className="text-foreground">
                  Course
                </Label>
                <Input
                  id="course"
                  value={formData.course}
                  onChange={(e) => setFormData({ ...formData, course: e.target.value })}
                  placeholder="e.g., Computer Science"
                  className="bg-input border-border"
                />
              </div>
            </>
          )}

          {mode !== "role" && (
            <div className="space-y-2">
              <Label htmlFor="status" className="text-foreground">
                Status
              </Label>
              <Select value={formData.status} onValueChange={(value) => setFormData({ ...formData, status: value })}>
                <SelectTrigger className="bg-input border-border">
                  <SelectValue placeholder="Select status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                  <SelectItem value="suspended">Suspended</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="flex justify-end gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" className="bg-primary text-primary-foreground hover:bg-primary/90">
              {mode === "add" ? "Add User" : mode === "role" ? "Update Role" : "Save Changes"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
