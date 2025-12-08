import type React from "react"
import { Logo } from "./logo"

interface AuthLayoutProps {
  children: React.ReactNode
}

export function AuthLayout({ children }: AuthLayoutProps) {
  return (
    <div className="min-h-screen gradient-bg flex items-center justify-center p-4">
      <div className="w-full max-w-5xl flex rounded-2xl overflow-hidden shadow-2xl">
        {/* Left side - Form */}
        <div className="w-full md:w-1/2 glass-card p-8 md:p-10">
          <Logo className="mb-8" />
          {children}
        </div>

        {/* Right side - Image */}
        <div className="hidden md:block w-[50%] relative">
          <img
            src="/library-login-right-cover.jpg"
            alt="Library books"
            className="absolute inset-0 w-full h-full object-cover rounded-r-2xl"
          />
        </div>
      </div>
    </div>
  )
}
