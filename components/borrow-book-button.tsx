"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { BookOpen, Loader2, Check, Clock } from "lucide-react"
import { createBorrowRequest } from "@/lib/actions/borrow-actions"
import { createReservation } from "@/lib/actions/reservation-actions"

interface BorrowBookButtonProps {
  bookId: string
  available: boolean
}

export function BorrowBookButton({ bookId, available }: BorrowBookButtonProps) {
  const [isLoading, setIsLoading] = useState(false)
  const [borrowSuccess, setBorrowSuccess] = useState(false)
  const [reserveSuccess, setReserveSuccess] = useState(false)
  const [error, setError] = useState("")

  const handleBorrow = async () => {
    setIsLoading(true)
    setError("")

    try {
      const result = await createBorrowRequest(bookId)
      if (result.error) {
        setError(result.error)
      } else {
        setBorrowSuccess(true)
      }
    } catch (err) {
      setError("Failed to submit request")
    } finally {
      setIsLoading(false)
    }
  }

  const handleReserve = async () => {
    setIsLoading(true)
    setError("")

    try {
      const result = await createReservation(bookId)
      if (result.error) {
        setError(result.error)
      } else {
        setReserveSuccess(true)
      }
    } catch (err) {
      setError("Failed to reserve book")
    } finally {
      setIsLoading(false)
    }
  }

  if (borrowSuccess) {
    return (
      <Button disabled className="bg-green-600 text-white px-8 py-6 text-base font-medium">
        <Check className="w-5 h-5 mr-2" />
        REQUEST SUBMITTED
      </Button>
    )
  }

  if (reserveSuccess) {
    return (
      <Button disabled className="bg-blue-600 text-white px-8 py-6 text-base font-medium">
        <Check className="w-5 h-5 mr-2" />
        RESERVED
      </Button>
    )
  }

  return (
    <div>
      {available ? (
        <Button
          onClick={handleBorrow}
          disabled={isLoading}
          className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-base font-medium"
        >
          {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : <BookOpen className="w-5 h-5 mr-2" />}
          BORROW BOOK REQUEST
        </Button>
      ) : (
        <Button
          onClick={handleReserve}
          disabled={isLoading}
          className="bg-blue-600 text-white hover:bg-blue-700 px-8 py-6 text-base font-medium"
        >
          {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : <Clock className="w-5 h-5 mr-2" />}
          RESERVE BOOK
        </Button>
      )}
      {error && <p className="text-destructive text-sm mt-2">{error}</p>}
    </div>
  )
}
