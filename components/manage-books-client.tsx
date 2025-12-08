"use client";

import { useState } from "react";
import { AdminBookCard } from "@/components/admin-book-card";
import { BookFormModal } from "@/components/book-form-modal";
import { DeleteConfirmModal } from "@/components/delete-confirm-modal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Search } from "lucide-react";
import { createBook, updateBook, deleteBook } from "@/lib/actions/book-actions";
import type { BookWithDetails, Category } from "@/lib/db";

interface ManageBooksClientProps {
  initialBooks: BookWithDetails[];
  categories: Category[]; // ✅ FIX: required for dropdown
}

export function ManageBooksClient({ initialBooks, categories }: ManageBooksClientProps) {
  const [books, setBooks] = useState(initialBooks);
  const [searchQuery, setSearchQuery] = useState("");
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [selectedBook, setSelectedBook] = useState<any>(null);

  const filteredBooks = books.filter((book) => {
    const b = book as any;
    const authorName = b.author_name || book.authors?.[0]?.name || "";
    const categoryName = b.category_name || book.categories?.[0]?.name || "";

    return (
      book.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      authorName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      categoryName.toLowerCase().includes(searchQuery.toLowerCase())
    );
  });

  const handleEdit = (id: string) => {
    const book = books.find((b) => b.id === id);
    if (!book) return;

    const b = book as any;

    setSelectedBook({
      id: book.id,
      title: book.title,
      isbn: book.isbn || "",
      author: b.author_name || book.authors?.[0]?.name || "",
      publisher: b.publisher_name || book.publisher?.name || "",
      category: b.category_name || book.categories?.[0]?.name || "",
      categoryId: b.category_id || "",
      yearPublished: book.publication_year?.toString() || "",
      totalCopies: String(book.total_copies),
      availableCopies: String(book.available_copies),
      description: book.description || "",
      coverUrl: book.cover_url || "",
      status: book.available_copies > 0 ? "Available" : "Borrowed",
    });

    setIsEditModalOpen(true);
  };

  const handleDelete = (id: string) => {
    const book = books.find((b) => b.id === id);
    if (book) {
      setSelectedBook(book);
      setIsDeleteModalOpen(true);
    }
  };

  const handleAddSubmit = async (data: any) => {
    const result = await createBook({
      title: data.title,
      isbn: data.isbn,
      description: data.description,
      cover_url: data.coverUrl,
      author_name: data.author,
      publisher_name: data.publisher,
      category_id: data.categoryId || null,
      publication_year: data.yearPublished ? Number(data.yearPublished) : undefined,
      total_copies: Number(data.totalCopies),
    });

    if (result.book) {
      window.location.reload();
    }
  };

  const handleEditSubmit = async (data: any) => {
    if (!selectedBook) return;

    await updateBook(selectedBook.id, {
      title: data.title,
      isbn: data.isbn,
      description: data.description,
      cover_url: data.coverUrl,
      author_name: data.author,
      publisher_name: data.publisher,
      category_id: data.categoryId || null,
      publication_year: data.yearPublished ? Number(data.yearPublished) : undefined,
      total_copies: Number(data.totalCopies),
      available_copies: Number(data.availableCopies),
    });

    window.location.reload();
  };

  const handleDeleteConfirm = async () => {
    if (!selectedBook) return;

    await deleteBook(selectedBook.id);
    setBooks((prev) => prev.filter((book) => book.id !== selectedBook.id));
    setIsDeleteModalOpen(false);
    setSelectedBook(null);
  };

  return (
    <main className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-1">Manage Books</h1>
          <p className="text-muted-foreground">Add, edit, or remove books from the library collection</p>
        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add New Book
        </Button>
      </div>

      {/* Search */}
      <div className="relative mb-8 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <Input
          placeholder="Search books by title, author, or category..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10 bg-input border-border"
        />
      </div>

      {/* Books Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-6">
        {filteredBooks.map((book) => {
          const b = book as any;

          return (
            <AdminBookCard
              key={book.id}
              id={book.id}
              title={book.title}
              author={b.author_name || book.authors?.[0]?.name || "Unknown Author"}
              category={b.category_name || book.categories?.[0]?.name || "General"}
              coverUrl={book.cover_url || "/abstract-book-cover.png"}
              coverColor="#1a1a2e"
              totalCopies={book.total_copies}
              availableCopies={book.available_copies}
              status={book.available_copies > 0 ? "Available" : "Borrowed"}
              onEdit={handleEdit}
              onDelete={handleDelete}
            />
          );
        })}
      </div>

      {/* No results */}
      {filteredBooks.length === 0 && (
        <div className="text-center py-16">
          <p className="text-muted-foreground">No books found matching your search.</p>
        </div>
      )}

      {/* ADD BOOK MODAL */}
      <BookFormModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSubmit={handleAddSubmit}
        mode="add"
        categories={categories}   // ✅ FIX
      />

      {/* EDIT BOOK MODAL */}
      <BookFormModal
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false);
          setSelectedBook(null);
        }}
        onSubmit={handleEditSubmit}
        initialData={selectedBook}
        mode="edit"
        categories={categories}   // ✅ FIX
      />

      {/* DELETE CONFIRM MODAL */}
      <DeleteConfirmModal
        isOpen={isDeleteModalOpen}
        onClose={() => {
          setIsDeleteModalOpen(false);
          setSelectedBook(null);
        }}
        onConfirm={handleDeleteConfirm}
        title="Delete Book"
        description={`Are you sure you want to delete "${selectedBook?.title}"? This action cannot be undone.`}
      />
    </main>
  );
}
