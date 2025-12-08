"use client"

import { LogOut } from "lucide-react"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { logoutAction } from "@/lib/actions/auth-actions"

export function LogoutButton() {
  const handleLogout = async () => {
    await logoutAction()
  }

  return (
    <DropdownMenuItem onClick={handleLogout} className="cursor-pointer">
      <LogOut className="mr-2 h-4 w-4" />
      Logout
    </DropdownMenuItem>
  )
}
