export const dynamic = "force-dynamic";
export const revalidate = 0;


import { AdminHeader } from "@/components/admin-header"
import { AdminTransactionsClient } from "@/components/admin-transactions-client"
import { getBorrowRequests } from "@/lib/actions/borrow-actions"

export default async function TransactionsPage() {
  const transactions = await getBorrowRequests()

  return (
    <div className="min-h-screen gradient-bg">
      <AdminHeader />
      <AdminTransactionsClient initialTransactions={transactions} />
    </div>
  )
}
