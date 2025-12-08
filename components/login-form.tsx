"use client"

import type React from "react"

import { useState } from "react"
import Link from "next/link"
import { Eye, EyeOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { loginAction } from "@/lib/actions/auth-actions"

export function LoginForm() {
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    const formData = new FormData(e.currentTarget)

    try {
      const result = await loginAction(formData)
      if (result?.error) {
        setError(result.error)
      }
    } catch (err) {
      // Redirect happens in server action, so this is for actual errors
      console.error(err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground mb-2">Welcome Back to LibraLink</h1>
      <p className="text-muted-foreground text-sm mb-8">Access the vast collection of resources, and stay updated</p>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="space-y-2">
          <Label htmlFor="email" className="text-muted-foreground text-sm">
            Email
          </Label>
          <Input
            id="email"
            name="email"
            type="email"
            placeholder="liomarley@gmail.com"
            required
            className="bg-input border-border text-foreground placeholder:text-muted-foreground"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="password" className="text-muted-foreground text-sm">
            Password
          </Label>
          <div className="relative">
            <Input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              placeholder="Atleast 8 characters long"
              required
              className="bg-input border-border text-foreground placeholder:text-muted-foreground pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
        </div>

        <Button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-medium py-5"
        >
          {isLoading ? "Logging in..." : "Login"}
        </Button>
      </form>

      <p className="text-center text-muted-foreground text-sm mt-6">
        Don't have an account already?{" "}
        <Link href="/register" className="text-accent hover:underline font-medium">
          Register here
        </Link>
      </p>
    </div>
  )
}
