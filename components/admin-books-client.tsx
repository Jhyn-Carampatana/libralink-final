"use client"

import { useState, useTransition } from "react"
import { AdminBookCard } from "@/components/admin-book-card"
import { BookFormModal } from "@/components/book-form-modal"
import { DeleteConfirmModal } from "@/components/delete-confirm-modal"
import { CategoryFormModal } from "@/components/category-form-modal"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Plus, Search, Edit, Trash2 } from "lucide-react"
import {
  createBook,
  updateBook,
  deleteBook,
  createCategory,
  updateCategory,
  deleteCategory,
} from "@/lib/actions/book-actions"
import type { BookWithDetails, Category } from "@/lib/db"

interface AdminBooksClientProps {
  initialBooks: BookWithDetails[]
  initialCategories: Category[]
}

export function AdminBooksClient({ initialBooks, initialCategories }: AdminBooksClientProps) {
  const [books, setBooks] = useState(initialBooks)
  const [categories, setCategories] = useState(initialCategories)
  const [activeTab, setActiveTab] = useState("books")  // ⭐ NEW
  const [searchQuery, setSearchQuery] = useState("")
  const [isPending, startTransition] = useTransition()

  const [isAddBookModalOpen, setIsAddBookModalOpen] = useState(false)
  const [isEditBookModalOpen, setIsEditBookModalOpen] = useState(false)
  const [isDeleteBookModalOpen, setIsDeleteBookModalOpen] = useState(false)
  const [selectedBook, setSelectedBook] = useState<BookWithDetails | null>(null)

  const [isCategoryModalOpen, setIsCategoryModalOpen] = useState(false)
  const [editingCategory, setEditingCategory] = useState<Category | null>(null)
  const [isDeleteCategoryModalOpen, setIsDeleteCategoryModalOpen] = useState(false)

  // ---------------------------
  // FILTERING
  // ---------------------------
  const filteredBooks = books.filter((book) => {
    const author = (book as any).author_name || book.authors?.[0]?.name || ""
    const category = (book as any).category_name || book.categories?.[0]?.name || ""
    const q = searchQuery.toLowerCase()
    return (
      book.title.toLowerCase().includes(q) ||
      author.toLowerCase().includes(q) ||
      category.toLowerCase().includes(q)
    )
  })

  // ---------------------------
  // Utility mappers
  // ---------------------------
  const mapBookToCardProps = (book: BookWithDetails) => {
    const b = book as any
    return {
      id: book.id,
      title: book.title,
      isbn: book.isbn || "",
      author: b.author_name || book.authors?.[0]?.name || "Unknown Author",
      publisher: b.publisher_name || book.publisher?.name || "",
      category: b.category_name || book.categories?.[0]?.name || "Uncategorized",
      categoryId: b.category_id || book.categories?.[0]?.id || "",
      coverUrl: book.cover_url || "/abstract-book-cover.png",
      coverColor: "#1a1a2e",
      totalCopies: book.total_copies,
      availableCopies: book.available_copies,
      yearPublished: book.publication_year?.toString() || "",
      description: book.description || "",
      status: book.available_copies > 0 ? "Available" : "Borrowed",
    }
  }

  const mapBookToFormData = (book: BookWithDetails) => {
    const card = mapBookToCardProps(book)
    return {
      ...card,
      totalCopies: String(card.totalCopies),
      availableCopies: String(card.availableCopies),
    }
  }

  // ---------------------------
  // BOOK HANDLERS
  // ---------------------------
  const handleEditBook = (id: string) => {
    const book = books.find((b) => b.id === id)
    if (book) {
      setSelectedBook(book)
      setIsEditBookModalOpen(true)
    }
  }

  const handleDeleteBook = (id: string) => {
    const b = books.find((x) => x.id === id)
    if (b) {
      setSelectedBook(b)
      setIsDeleteBookModalOpen(true)
    }
  }

  const handleAddBookSubmit = async (data: any) => {
    startTransition(async () => {
      const { book } = await createBook({
        title: data.title,
        isbn: data.isbn,
        description: data.description,
        cover_url: data.coverUrl || "/abstract-book-cover.png",
        author_name: data.author,
        publisher_name: data.publisher,
        category_id: data.categoryId || null,
        publication_year: data.yearPublished ? Number.parseInt(data.yearPublished) : undefined,
        total_copies: Number.parseInt(data.totalCopies) || 1,
      })

      if (book) {
        const cat = categories.find((c) => c.id === data.categoryId)
        const newBook: BookWithDetails = {
          ...book,
          author_name: data.author,
          publisher_name: data.publisher,
          category_name: cat?.name || data.category,
          authors: [{ id: "1", name: data.author }],
          categories: cat ? [{ id: cat.id, name: cat.name }] : [],
          publisher: data.publisher ? { id: "1", name: data.publisher } : null,
        } as any

        setBooks((prev) => [newBook, ...prev])
        setIsAddBookModalOpen(false)
      }
    })
  }

  const handleEditBookSubmit = async (data: any) => {
    if (!selectedBook) return

    startTransition(async () => {
      const { book } = await updateBook(selectedBook.id, {
        title: data.title,
        isbn: data.isbn,
        description: data.description,
        cover_url: data.coverUrl,
        author_name: data.author,
        publisher_name: data.publisher,
        category_id: data.categoryId || null,
        publication_year: data.yearPublished ? Number.parseInt(data.yearPublished) : undefined,
        total_copies: Number.parseInt(data.totalCopies),
        available_copies: Number.parseInt(data.availableCopies) || selectedBook.available_copies,
      })

      if (book) {
        const cat = categories.find((c) => c.id === data.categoryId)

        setBooks((prev) =>
          prev.map((b) =>
            b.id === selectedBook.id
              ? ({
                  ...b,
                  ...book,
                  author_name: data.author,
                  publisher_name: data.publisher,
                  category_name: cat?.name || data.category,
                  authors: [{ id: "1", name: data.author }],
                  categories: cat ? [{ id: cat.id, name: cat.name }] : b.categories,
                  publisher: data.publisher ? { id: "1", name: data.publisher } : null,
                } as any)
              : b,
          ),
        )

        setIsEditBookModalOpen(false)
        setSelectedBook(null)
      }
    })
  }

  const handleDeleteBookConfirm = async () => {
    if (!selectedBook) return
    startTransition(async () => {
      const { error } = await deleteBook(selectedBook.id)
      if (!error) {
        setBooks((prev) => prev.filter((b) => b.id !== selectedBook.id))
        setIsDeleteBookModalOpen(false)
        setSelectedBook(null)
      }
    })
  }

  // ---------------------------
  // CATEGORY HANDLERS
  // ---------------------------
  const handleAddCategory = () => {
    setEditingCategory(null)
    setIsCategoryModalOpen(true)
  }

  const handleEditCategory = (category: Category) => {
    setEditingCategory(category)
    setIsCategoryModalOpen(true)
  }

  const handleDeleteCategory = (category: Category) => {
    setEditingCategory(category)
    setIsDeleteCategoryModalOpen(true)
  }

  const handleCategorySubmit = async (data: { name: string }) => {
    startTransition(async () => {
      if (editingCategory) {
        const { category, error } = await updateCategory(editingCategory.id, { name: data.name })
        if (!error && category) {
          setCategories((prev) => prev.map((c) => (c.id === category.id ? category : c)))
        }
      } else {
        const { category, error } = await createCategory({ name: data.name })
        if (!error && category) {
          setCategories((prev) => [category, ...prev])
        }
      }

      setIsCategoryModalOpen(false)
      setEditingCategory(null)
    })
  }

  const handleCategoryDeleteConfirm = async () => {
    if (!editingCategory) return
    startTransition(async () => {
      const { error } = await deleteCategory(editingCategory.id)
      if (!error) {
        setCategories((prev) => prev.filter((c) => c.id !== editingCategory.id))
        setIsDeleteCategoryModalOpen(false)
        setEditingCategory(null)
      }
    })
  }

  // ---------------------------
  // UI
  // ---------------------------
  return (
    <main className="container mx-auto px-4 py-8">

      {/* HEADER ROW */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Book Administration</h1>
          <p className="text-muted-foreground">Manage books and categories</p>
        </div>

        <div className="flex gap-2">
          {activeTab === "books" && (
            <Button
              onClick={() => setIsAddBookModalOpen(true)}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add New Book
            </Button>
          )}

          {activeTab === "categories" && (
            <Button
              onClick={handleAddCategory}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Category
            </Button>
          )}
        </div>
      </div>

      {/* TABS */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="mb-6 bg-secondary/50">
          <TabsTrigger
            value="books"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Books ({books.length})
          </TabsTrigger>
          <TabsTrigger
            value="categories"
            className="data-[state=active]:bg-accent data-[state=active]:text-accent-foreground"
          >
            Categories ({categories.length})
          </TabsTrigger>
        </TabsList>

        {/* BOOKS TAB */}
        <TabsContent value="books">
          <div className="relative mb-8 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
            <Input
              placeholder="Search books by title, author, or category..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-input border-border"
            />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
            {filteredBooks.map((book) => (
              <AdminBookCard
                key={book.id}
                {...mapBookToCardProps(book)}
                onEdit={handleEditBook}
                onDelete={handleDeleteBook}
              />
            ))}
          </div>

          {filteredBooks.length === 0 && (
            <div className="text-center py-16 glass-card rounded-2xl">
              <p className="text-muted-foreground">No books found.</p>
            </div>
          )}
        </TabsContent>

        {/* CATEGORIES TAB */}
        <TabsContent value="categories">
          <div className="grid gap-4">
            {categories.length > 0 ? (
              categories.map((category) => (
                <Card key={category.id} className="glass-card p-4 flex items-center justify-between">
                  <h3 className="font-semibold text-foreground">{category.name}</h3>

                  <div className="flex gap-2">
                    <Button variant="ghost" size="icon" onClick={() => handleEditCategory(category)}>
                      <Edit className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="text-destructive hover:bg-destructive/20"
                      onClick={() => handleDeleteCategory(category)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </Card>
              ))
            ) : (
              <div className="text-center py-16 glass-card rounded-2xl">
                <p className="text-muted-foreground">No categories found.</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* MODALS */}
      <BookFormModal
        isOpen={isAddBookModalOpen}
        onClose={() => setIsAddBookModalOpen(false)}
        onSubmit={handleAddBookSubmit}
        mode="add"
        categories={categories}
      />

      <BookFormModal
        isOpen={isEditBookModalOpen}
        onClose={() => {
          setIsEditBookModalOpen(false)
          setSelectedBook(null)
        }}
        onSubmit={handleEditBookSubmit}
        initialData={selectedBook ? mapBookToFormData(selectedBook) : undefined}
        mode="edit"
        categories={categories}
      />

      <DeleteConfirmModal
        isOpen={isDeleteBookModalOpen}
        onClose={() => {
          setIsDeleteBookModalOpen(false)
          setSelectedBook(null)
        }}
        onConfirm={handleDeleteBookConfirm}
        title="Delete Book"
        description={`Are you sure you want to delete "${selectedBook?.title}"?`}
      />

      {/* CATEGORY MODALS */}
      <CategoryFormModal
        isOpen={isCategoryModalOpen}
        onClose={() => {
          setIsCategoryModalOpen(false)
          setEditingCategory(null)
        }}
        onSubmit={handleCategorySubmit}
        initialData={editingCategory ? { id: editingCategory.id, name: editingCategory.name } : null}
        mode={editingCategory ? "edit" : "add"}
      />

      <DeleteConfirmModal
        isOpen={isDeleteCategoryModalOpen}
        onClose={() => {
          setIsDeleteCategoryModalOpen(false)
          setEditingCategory(null)
        }}
        onConfirm={handleCategoryDeleteConfirm}
        title="Delete Category"
        description={`Are you sure you want to delete "${editingCategory?.name}"?`}
      />
    </main>
  )
}
