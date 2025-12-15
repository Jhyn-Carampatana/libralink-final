export const dynamic = "force-dynamic";
export const revalidate = 0;

import { redirect } from "next/navigation"
import { Header } from "@/components/header"
import { BookCard } from "@/components/book-card"
import { getBookById, getBooks } from "@/lib/actions/book-actions"
import { BorrowBookButton } from "@/components/borrow-book-button"

export default async function BookDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const book = await getBookById(id)

  if (!book) {
    redirect("/dashboard")
  }

  const allBooks = await getBooks()
  const otherBooks = allBooks.filter((b) => b.id !== book.id)

  const b = book as any
  const authorName = b.author_name || book.authors?.[0]?.name || "Unknown Author"
  const categoryName = b.category_name || book.categories?.[0]?.name || "Uncategorized"

  return (
    <div className="min-h-screen gradient-bg">
      <Header />

      <main className="container mx-auto px-4 py-12">
        <div className="max-w-6xl mx-auto mb-16">
          <div className="grid md:grid-cols-2 gap-12 items-start">
            <div>
              <h1 className="text-5xl font-bold text-foreground mb-4 leading-tight">{book.title}</h1>

              <div className="flex items-center gap-4 mb-6 flex-wrap">
                <p className="text-muted-foreground">
                  By <span className="text-foreground font-medium">{authorName}</span>
                </p>
                <span className="text-muted-foreground">•</span>
                <p className="text-muted-foreground">
                  Category: <span className="text-accent">{categoryName}</span>
                </p>
              </div>

              <div className="flex gap-8 mb-6">
                <div>
                  <p className="text-muted-foreground text-sm mb-1">Total books:</p>
                  <p className="text-foreground font-semibold text-xl">{book.total_copies}</p>
                </div>
                <div>
                  <p className="text-muted-foreground text-sm mb-1">Available books:</p>
                  <p className="text-accent font-semibold text-xl">{book.available_copies}</p>
                </div>
              </div>

              {book.description && (
                <p className="text-muted-foreground text-sm leading-relaxed mb-8">{book.description}</p>
              )}

              <BorrowBookButton bookId={book.id} available={book.available_copies > 0} />
            </div>

            <div className="flex justify-center md:justify-end">
              <div className="relative">
                <div className="w-64 h-96 rounded-lg overflow-hidden shadow-2xl">
                  <img
                    src={book.cover_url || "/placeholder.svg?height=384&width=256&query=book cover"}
                    alt={book.title}
                    className="w-full h-full object-cover"
                  />
                </div>
                {/* Decorative blur effect behind */}
                <div className="absolute -inset-4 -z-10 bg-accent/20 blur-2xl rounded-full" />
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-6xl mx-auto">
          <h2 className="text-2xl font-bold text-foreground mb-8">All Books</h2>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-6">
            {otherBooks.map((pb) => {
              const pbook = pb as any
              return (
                <BookCard
                  key={pb.id}
                  id={pb.id}
                  title={pb.title}
                  author={pbook.author_name || pb.authors?.[0]?.name || "Unknown"}
                  category={pbook.category_name || pb.categories?.[0]?.name || ""}
                  coverUrl={pb.cover_url || "/abstract-book-cover.png"}
                />
              )
            })}
          </div>
        </div>
      </main>
    </div>
  )
}
