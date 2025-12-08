"use client"

import type React from "react"
import { useState, useEffect, useRef } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Upload, X, AlertCircle } from "lucide-react"

interface BookFormData {
  id?: string
  title: string
  isbn: string
  author: string
  publisher: string
  category: string
  categoryId?: string
  yearPublished: string
  totalCopies: string
  availableCopies?: string
  coverUrl: string
  description: string
  status: string
}

interface BookFormModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: BookFormData) => void
  initialData?: BookFormData | null
  mode: "add" | "edit"
  categories?: Array<{ id: string; name: string }>
}

const defaultFormData: BookFormData = {
  title: "",
  isbn: "",
  author: "",
  publisher: "",
  category: "",
  categoryId: "",
  yearPublished: "",
  totalCopies: "1",
  availableCopies: "1",
  coverUrl: "",
  description: "",
  status: "Available",
}

const statuses = ["Available", "Borrowed", "Reserved", "Lost"]

export function BookFormModal({ isOpen, onClose, onSubmit, initialData, mode, categories }: BookFormModalProps) {
  const [formData, setFormData] = useState<BookFormData>(defaultFormData)
  const [coverPreview, setCoverPreview] = useState<string | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (initialData) {
      setFormData({
        id: initialData.id,
        title: initialData.title ?? "",
        isbn: initialData.isbn ?? "",
        author: initialData.author ?? "",
        publisher: initialData.publisher ?? "",
        category: initialData.category ?? "",
        categoryId: initialData.categoryId ?? "",
        yearPublished: initialData.yearPublished ?? "",
        totalCopies: String(initialData.totalCopies ?? "1"),
        availableCopies: String(initialData.availableCopies ?? "0"),
        coverUrl: initialData.coverUrl ?? "",
        description: initialData.description ?? "",
        status: initialData.status ?? "Available",
      })
      setCoverPreview(initialData.coverUrl || null)
    } else {
      setFormData(defaultFormData)
      setCoverPreview(null)
    }
  }, [initialData, isOpen])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const totalCopiesNum = Number(formData.totalCopies)
    const availableCopiesNum = Number(formData.availableCopies ?? "0")

    if (mode === "edit" && totalCopiesNum < availableCopiesNum) {
      setValidationError("Total copies cannot be less than available copies")
      return
    }

    onSubmit({
      ...formData,
      coverUrl: coverPreview || formData.coverUrl,
    })

    onClose()
  }

  const handleChange = (field: keyof BookFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    setValidationError(null)
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onloadend = () => {
      const base64 = reader.result as string
      setCoverPreview(base64)
      setFormData((prev) => ({ ...prev, coverUrl: base64 }))
    }
    reader.readAsDataURL(file)
  }

  const handleRemoveCover = () => {
    setCoverPreview(null)
    setFormData((prev) => ({ ...prev, coverUrl: "" }))
    if (fileInputRef.current) fileInputRef.current.value = ""
  }

  const categoryOptions = categories ?? []

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="glass-card border-border max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-xl font-semibold text-foreground">
            {mode === "add" ? "Add New Book" : "Edit Book"}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4 mt-4">
          {validationError && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/20 border border-destructive/50 text-destructive">
              <AlertCircle className="w-4 h-4" />
              <span className="text-sm">{validationError}</span>
            </div>
          )}

          {/* Title + ISBN */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Book Title</Label>
              <Input
                value={formData.title}
                onChange={(e) => handleChange("title", e.target.value)}
                placeholder="Enter book title"
                required
              />
            </div>
            <div>
              <Label>ISBN</Label>
              <Input
                value={formData.isbn}
                onChange={(e) => handleChange("isbn", e.target.value)}
                placeholder="Enter ISBN"
                required
              />
            </div>
          </div>

          {/* Author + Publisher */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Author</Label>
              <Input
                value={formData.author}
                onChange={(e) => handleChange("author", e.target.value)}
                placeholder="Enter author name"
                required
              />
            </div>
            <div>
              <Label>Publisher</Label>
              <Input
                value={formData.publisher}
                onChange={(e) => handleChange("publisher", e.target.value)}
                placeholder="Enter publisher"
              />
            </div>
          </div>

          {/* Category + Year */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Category</Label>
              <Select
                value={formData.categoryId}
                onValueChange={(value) => handleChange("categoryId", value)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select category" />
                </SelectTrigger>
                <SelectContent>
                  {categoryOptions.map((cat) => (
                    <SelectItem key={cat.id} value={cat.id}>
                      {cat.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>Year Published</Label>
              <Input
                type="number"
                value={formData.yearPublished}
                onChange={(e) => handleChange("yearPublished", e.target.value)}
                placeholder="e.g., 2023"
              />
            </div>
          </div>

          {/* Copies */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Total Copies</Label>
              <Input
                type="number"
                min="0"
                value={formData.totalCopies}
                onChange={(e) => handleChange("totalCopies", e.target.value)}
              />
            </div>

            {mode === "edit" && (
              <div>
                <Label>Available Copies</Label>
                <Input
                  type="number"
                  min="0"
                  value={formData.availableCopies}
                  onChange={(e) => handleChange("availableCopies", e.target.value)}
                />
              </div>
            )}
          </div>

          {/* Description */}
          <div>
            <Label>Description</Label>
            <Textarea
              value={formData.description}
              onChange={(e) => handleChange("description", e.target.value)}
              placeholder="Enter book description"
              rows={3}
            />
          </div>

          {/* Cover Image */}
          <div>
            <Label>Cover Image</Label>
            {coverPreview ? (
              <div className="relative inline-block">
                <img
                  src={coverPreview}
                  alt="Cover preview"
                  className="w-32 h-48 object-cover rounded-lg border"
                />
                <button
                  type="button"
                  onClick={handleRemoveCover}
                  className="absolute -top-2 -right-2 p-1 rounded-full bg-destructive text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed rounded-xl p-6 text-center cursor-pointer"
              >
                <Upload className="w-8 h-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm">Click to upload or drag and drop</p>
                <p className="text-xs text-muted-foreground mt-1">PNG, JPG up to 5MB</p>
              </div>
            )}

            <input
              type="file"
              ref={fileInputRef}
              accept="image/*"
              onChange={handleFileChange}
              className="hidden"
            />
          </div>

          {/* Buttons */}
          <div className="flex gap-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1">
              Cancel
            </Button>
            <Button type="submit" className="flex-1">
              {mode === "add" ? "Add Book" : "Save Changes"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}
