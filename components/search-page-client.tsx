"use client"
import { useState, useEffect } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { BookCard } from "@/components/book-card"
import { Search, X, FileX, Loader2 } from "lucide-react"
import { getBooks } from "@/lib/actions/book-actions"

export function SearchPageClient() {
  const [searchQuery, setSearchQuery] = useState("")
  const [hasSearched, setHasSearched] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [searchResults, setSearchResults] = useState<any[]>([])

  // Debounced search
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([])
      return
    }

    const timer = setTimeout(async () => {
      setIsLoading(true)
      setHasSearched(true)
      try {
        const results = await getBooks(searchQuery)
        setSearchResults(results)
      } catch (error) {
        console.error("Search error:", error)
        setSearchResults([])
      } finally {
        setIsLoading(false)
      }
    }, 300)

    return () => clearTimeout(timer)
  }, [searchQuery])

  const clearSearch = () => {
    setSearchQuery("")
    setHasSearched(false)
    setSearchResults([])
  }

  return (
    <main className="container mx-auto px-4 py-12">
      <div className="max-w-4xl mx-auto">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <p className="text-accent uppercase text-sm tracking-wider mb-4">DISCOVER YOUR NEXT GREAT READ:</p>
          <h1 className="text-4xl md:text-5xl font-bold text-foreground mb-2 leading-tight">Explore and Search for</h1>
          <h2 className="text-4xl md:text-5xl font-bold mb-8">
            <span className="text-accent">Any Book</span> <span className="text-foreground">In Our Library</span>
          </h2>

          {/* Search Bar */}
          <div className="max-w-2xl mx-auto">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground w-5 h-5" />
              <Input
                type="text"
                placeholder="Search by title, author, or category..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-12 pr-12 py-6 bg-input border-border text-foreground placeholder:text-muted-foreground text-base rounded-xl"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={clearSearch}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="w-5 h-5" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Search Results */}
        {hasSearched && (
          <div className="mt-12">
            <h3 className="text-xl font-semibold text-foreground mb-6">Search Result for {searchQuery || "..."}</h3>

            {isLoading ? (
              <div className="flex justify-center py-16">
                <Loader2 className="w-8 h-8 animate-spin text-accent" />
              </div>
            ) : searchResults.length > 0 ? (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-6">
                {searchResults.map((book) => {
                  const authorName = book.author_name || book.authors?.[0]?.name || "Unknown"
                  const categoryName = book.category_name || book.categories?.[0]?.name || "General"
                  return (
                    <BookCard
                      key={book.id}
                      id={book.id}
                      title={book.title}
                      author={authorName}
                      category={categoryName}
                      coverUrl={book.cover_url || undefined}
                      coverColor="#2a2a4a"
                    />
                  )
                })}
              </div>
            ) : (
              /* Empty State */
              <div className="flex flex-col items-center justify-center py-16">
                <div className="w-28 h-28 rounded-full bg-secondary flex items-center justify-center mb-6">
                  <FileX className="w-12 h-12 text-muted-foreground" />
                </div>
                <h4 className="text-xl font-semibold text-foreground mb-2">No Results Found</h4>
                <p className="text-muted-foreground text-center max-w-md mb-6">
                  We couldn't find any books matching your search.
                  <br />
                  Try using different keywords or check for typos.
                </p>
                <Button
                  onClick={clearSearch}
                  variant="outline"
                  className="border-primary text-primary hover:bg-primary hover:text-primary-foreground bg-transparent"
                >
                  CLEAR SEARCH
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  )
}
