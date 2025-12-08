export const dynamic = "force-dynamic";
export const revalidate = 0;

import { Header } from "@/components/header"
import { ProfileCard } from "@/components/profile-card"
import { BorrowedBookCard } from "@/components/borrowed-book-card"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { getUserBorrowedBooks } from "@/lib/actions/borrow-actions"

export default async function ProfilePage() {
  const { user } = await getSession()

  if (!user) {
    redirect("/login")
  }

  const borrowedBooks = await getUserBorrowedBooks(user.id)

  return (
    <div className="min-h-screen gradient-bg">
      <Header />

      <main className="container mx-auto px-4 py-8">
        <div className="max-w-6xl mx-auto">
          <div className="grid lg:grid-cols-3 gap-8">
            {/* Left - Profile Card */}
            <div className="lg:col-span-1">
              <ProfileCard user={user} />
            </div>

            {/* Right - Borrowed Books */}
            <div className="lg:col-span-2">
              <h2 className="text-2xl font-bold text-foreground mb-6">Borrowed books</h2>

              {borrowedBooks.length > 0 ? (
                <div className="grid sm:grid-cols-2 gap-4">
                  {borrowedBooks.map((borrow: any) => {
                    const dueDate = new Date(borrow.due_date)
                    const today = new Date()
                    const daysLeft = Math.ceil((dueDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24))
                    const isOverdue = daysLeft < 0

                    return (
                      <BorrowedBookCard
                        key={borrow.id}
                        title={borrow.book.title}
                        author={borrow.book.authors?.map((a: any) => a.name).join(", ") || "Unknown"}
                        category={borrow.book.categories?.map((c: any) => c.name).join(" / ") || "General"}
                        coverUrl={borrow.book.cover_url}
                        coverColor="#2a2a4a"
                        borrowDate={new Date(borrow.approved_at).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                        })}
                        daysLeft={Math.abs(daysLeft)}
                        isOverdue={isOverdue}
                      />
                    )
                  })}
                </div>
              ) : (
                <div className="text-center py-12 bg-card/50 rounded-xl border border-border">
                  <p className="text-muted-foreground">You haven't borrowed any books yet.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
