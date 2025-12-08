import { Header } from "@/components/header"
import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { SearchPageClient } from "@/components/search-page-client"

export default async function SearchPage() {
  const { user } = await getSession()

  if (!user) {
    redirect("/login")
  }

  return (
    <div className="min-h-screen gradient-bg">
      <Header />
      <SearchPageClient />
    </div>
  )
}
