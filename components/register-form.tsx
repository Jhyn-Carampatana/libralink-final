"use client"

import type React from "react"

import { useState, useRef } from "react"
import Link from "next/link"
import { Eye, EyeOff, Upload } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { registerAction } from "@/lib/actions/auth-actions"

export function RegisterForm() {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [fileName, setFileName] = useState("")
  const [error, setError] = useState("")

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setFileName(file.name)
    }
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    const formData = new FormData(e.currentTarget)
    // Add university name
    formData.set("universityName", "WebDev Mastery University")

    try {
      const result = await registerAction(formData)
      if (result?.error) {
        setError(result.error)
      }
    } catch (err) {
      console.error(err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground mb-2">Create Your Library Account</h1>
      <p className="text-muted-foreground text-sm mb-6">
        Please complete all fields and upload a valid university ID to gain access to the library
      </p>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="fullName" className="text-muted-foreground text-sm">
            Full name
          </Label>
          <Input
            id="fullName"
            name="fullName"
            type="text"
            placeholder="Lawrence Marley"
            required
            className="bg-input border-border text-foreground placeholder:text-muted-foreground"
          />
        </div>

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
          <Label htmlFor="universityId" className="text-muted-foreground text-sm">
            University ID Number
          </Label>
          <div className="relative">
            <Input
              id="universityId"
              name="universityId"
              type="text"
              placeholder="eg: 394365762"
              required
              className="bg-input border-border text-foreground placeholder:text-muted-foreground pr-10"
            />
            <Eye size={18} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          </div>
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
              minLength={8}
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

        <div className="space-y-2">
          <Label className="text-muted-foreground text-sm">Upload University ID Card (file upload)</Label>
          <input type="file" ref={fileInputRef} onChange={handleFileChange} accept="image/*,.pdf" className="hidden" />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg bg-input border border-border text-muted-foreground hover:bg-muted transition-colors"
          >
            <Upload size={18} />
            {fileName || "Upload a file"}
          </button>
        </div>

        <Button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-medium py-5 mt-2"
        >
          {isLoading ? "Creating account..." : "Sign Up"}
        </Button>
      </form>

      <p className="text-center text-muted-foreground text-sm mt-6">
        Have an account already?{" "}
        <Link href="/login" className="text-accent hover:underline font-medium">
          Login
        </Link>
      </p>
    </div>
  )
}
