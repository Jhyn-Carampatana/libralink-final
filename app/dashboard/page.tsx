export const dynamic = "force-dynamic";
export const revalidate = 0;

import { Header } from "@/components/header"
import { BookCard } from "@/components/book-card"
import { getFeaturedBook, getBooks } from "@/lib/actions/book-actions"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { BorrowBookButton } from "@/components/borrow-book-button"

export default async function DashboardPage() {
  const { user } = await getSession()

  if (!user) {
    redirect("/login")
  }

  const [featuredBook, allBooks] = await Promise.all([getFeaturedBook(), getBooks()])

  // Fallback if no featured book
  const displayBook = featuredBook || {
    id: "1",
    title: "Welcome to LibraLink",
    description: "Your library is empty. Add some books to get started!",
    authors: [],
    categories: [],
    total_copies: 0,
    available_copies: 0,
    cover_url: "/abstract-book-cover.png",
  }

  const db = displayBook as any
  const authorNames = db.author_name || displayBook.authors?.[0]?.name || "Unknown Author"
  const categoryNames = db.category_name || displayBook.categories?.[0]?.name || "General"

  return (
    <div className="min-h-screen gradient-bg">
      <Header />

      <main className="container mx-auto px-4 py-12">
        {/* Featured Book Section */}
        <div className="max-w-6xl mx-auto mb-16">
          <div className="grid md:grid-cols-2 gap-12 items-start">
            {/* Left - Book Info */}
            <div>
              <h1 className="text-5xl font-bold text-foreground mb-4 leading-tight">{displayBook.title}</h1>

              <div className="flex items-center gap-4 mb-6 flex-wrap">
                <p className="text-muted-foreground">
                  By <span className="text-foreground font-medium">{authorNames}</span>
                </p>
                <span className="text-muted-foreground">•</span>
                <p className="text-muted-foreground">
                  Category: <span className="text-accent">{categoryNames}</span>
                </p>
              </div>

              <div className="flex gap-8 mb-6">
                <div>
                  <p className="text-muted-foreground text-sm mb-1">Total books:</p>
                  <p className="text-foreground font-semibold text-xl">{displayBook.total_copies}</p>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-1">Available books:</p>
                  <p className="text-accent font-semibold text-xl">{displayBook.available_copies}</p>
                </div>
              </div>

              <p className="text-muted-foreground text-sm leading-relaxed mb-8">
                {displayBook.description || "No description available."}
              </p>

              {featuredBook && (
                <BorrowBookButton bookId={featuredBook.id} available={featuredBook.available_copies > 0} />
              )}
            </div>

            {/* Right - Book Cover */}
            <div className="flex justify-center md:justify-end">
              <div className="relative">
                <div className="w-64 h-96 rounded-lg overflow-hidden shadow-2xl">
                  <img
                    src={displayBook.cover_url || "/placeholder.svg?height=384&width=256&query=book cover"}
                    alt={displayBook.title}
                    className="w-full h-full object-cover"
                  />
                </div>
                {/* Decorative blur effect behind */}
                <div className="absolute -inset-4 -z-10 bg-accent/20 blur-2xl rounded-full" />
              </div>
            </div>
          </div>
        </div>

        {/* All Books Section */}
        <div className="max-w-6xl mx-auto">
          <h2 className="text-2xl font-bold text-foreground mb-8">All Books</h2>

          {allBooks.length > 0 ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-6">
              {allBooks.map((book) => {
                const b = book as any
                return (
                  <BookCard
                    key={book.id}
                    id={book.id}
                    title={book.title}
                    author={b.author_name || book.authors?.[0]?.name || "Unknown"}
                    category={b.category_name || book.categories?.[0]?.name || "General"}
                    coverUrl={book.cover_url || undefined}
                  />
                )
              })}
            </div>
          ) : (
            <p className="text-muted-foreground text-center py-12">No books available yet.</p>
          )}
        </div>
      </main>
    </div>
  )
}
