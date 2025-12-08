"use server"

import { sql } from "@/lib/db"

export async function getLibraryStats() {
  try {
    const [bookStats, borrowStats, reservationStats, fineStats] = await Promise.all([
      sql`
        SELECT 
          COUNT(*) as total_books,
          SUM(total_copies) as total_copies,
          SUM(available_copies) as available_copies,
          SUM(total_copies - available_copies) as borrowed_copies
        FROM books
      `,
      sql`
        SELECT 
          COUNT(*) FILTER (WHERE status = 'pending') as pending,
          COUNT(*) FILTER (WHERE status = 'approved') as active,
          COUNT(*) FILTER (WHERE status = 'approved' AND due_date < CURRENT_DATE) as overdue,
          COUNT(*) FILTER (WHERE status = 'returned') as returned
        FROM borrow_requests
      `,
      sql`
        SELECT 
          COUNT(*) FILTER (WHERE status = 'active') as active
        FROM reservations
      `,
      sql`
        SELECT 
          COALESCE(SUM(amount) FILTER (WHERE status = 'unpaid'), 0) as unpaid_amount
        FROM fines
      `,
    ])

    return {
      totalBooks: Number(bookStats[0]?.total_books) || 0,
      booksBorrowed: Number(borrowStats[0]?.active) || 0,
      overdueBooks: Number(borrowStats[0]?.overdue) || 0,
      activeReservations: Number(reservationStats[0]?.active) || 0,
      unpaidFines: Number(fineStats[0]?.unpaid_amount) || 0,
    }
  } catch (error) {
    console.error("Get library stats error:", error)
    return {
      totalBooks: 0,
      booksBorrowed: 0,
      overdueBooks: 0,
      activeReservations: 0,
      unpaidFines: 0,
    }
  }
}

export async function getAdminStats() {
  try {
    const [userStats, libraryStats] = await Promise.all([
      sql`
        SELECT 
          COUNT(*) as total_users,
          COUNT(*) FILTER (WHERE role = 'student') as students,
          COUNT(*) FILTER (WHERE role = 'faculty') as faculty,
          COUNT(*) FILTER (WHERE role = 'librarian') as librarians,
          COUNT(*) FILTER (WHERE role = 'admin') as admins
        FROM users
      `,
      getLibraryStats(),
    ])

    return {
      users: {
        total: Number(userStats[0]?.total_users) || 0,
        students: Number(userStats[0]?.students) || 0,
        faculty: Number(userStats[0]?.faculty) || 0,
        librarians: Number(userStats[0]?.librarians) || 0,
        admins: Number(userStats[0]?.admins) || 0,
      },
      library: libraryStats,
    }
  } catch (error) {
    console.error("Get admin stats error:", error)
    return {
      users: { total: 0, students: 0, faculty: 0, librarians: 0, admins: 0 },
      library: { totalBooks: 0, booksBorrowed: 0, overdueBooks: 0, activeReservations: 0, unpaidFines: 0 },
    }
  }
}
