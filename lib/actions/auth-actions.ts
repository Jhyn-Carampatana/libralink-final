"use server"

import { signIn, signUp, signOut, getSession } from "@/lib/auth"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"

export async function loginAction(formData: FormData) {
  const email = formData.get("email") as string
  const password = formData.get("password") as string

  const { user, token, error } = await signIn(email, password)

  if (error || !token) {
    return { error: error || "Failed to sign in" }
  }

  const cookieStore = await cookies()
  cookieStore.set("session_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60, // 7 days
    path: "/",
  })

  // Redirect based on role
  if (user?.role === "admin") {
    redirect("/admin")
  } else if (user?.role === "librarian") {
    redirect("/librarian")
  } else {
    redirect("/dashboard")
  }
}

export async function registerAction(formData: FormData) {
  const email = formData.get("email") as string
  const password = formData.get("password") as string
  const fullName = formData.get("fullName") as string
  const universityId = formData.get("universityId") as string
  const universityName = formData.get("universityName") as string

  const { user, error } = await signUp(email, password, fullName, universityId, universityName)

  if (error || !user) {
    return { error: error || "Failed to create account" }
  }

  // Auto sign in after registration
  const { token, error: signInError } = await signIn(email, password)

  if (signInError || !token) {
    return { error: "Account created. Please sign in." }
  }

  const cookieStore = await cookies()
  cookieStore.set("session_token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60,
    path: "/",
  })

  redirect("/dashboard")
}

export async function logoutAction() {
  const cookieStore = await cookies()
  const token = cookieStore.get("session_token")?.value

  if (token) {
    await signOut(token)
    cookieStore.delete("session_token")
  }

  redirect("/login")
}

export async function getCurrentUser() {
  const { user } = await getSession()
  return user
}
