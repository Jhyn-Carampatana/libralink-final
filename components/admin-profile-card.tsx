"use client"

import type React from "react"

import { useState } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { BadgeCheck, Shield, KeyRound, Edit, Loader2 } from "lucide-react"
import { updateCurrentUserProfile, updateCurrentUserPassword } from "@/lib/actions/user-actions"

interface AdminProfileCardProps {
  name: string
  email: string
  role: string
  avatar: string
  joinDate: string
  lastLogin: string
  universityId?: string
  universityName?: string
  department?: string
  yearLevel?: string
  course?: string
  userId?: string
}

export function AdminProfileCard({
  name,
  email,
  role,
  avatar,
  joinDate,
  lastLogin,
  universityId,
  universityName,
  department,
  yearLevel,
  course,
  userId,
}: AdminProfileCardProps) {
  const [isEditOpen, setIsEditOpen] = useState(false)
  const [isPasswordOpen, setIsPasswordOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  // Edit form state
  const [editName, setEditName] = useState(name)
  const [editEmail, setEditEmail] = useState(email)

  // Password form state
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  const handleUpdateInfo = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")
    setSuccess("")

    try {
      const result = await updateCurrentUserProfile({
        full_name: editName,
        email: editEmail,
      })
      if (result.error) {
        setError(result.error)
      } else {
        setSuccess("Profile updated successfully!")
        setTimeout(() => {
          setIsEditOpen(false)
          setSuccess("")
          window.location.reload()
        }, 1500)
      }
    } catch (err) {
      setError("Failed to update profile")
    } finally {
      setIsLoading(false)
    }
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")
    setSuccess("")

    if (newPassword !== confirmPassword) {
      setError("New passwords do not match")
      setIsLoading(false)
      return
    }

    if (newPassword.length < 6) {
      setError("Password must be at least 6 characters")
      setIsLoading(false)
      return
    }

    try {
      const result = await updateCurrentUserPassword(currentPassword, newPassword)
      if (result.error) {
        setError(result.error)
      } else {
        setSuccess("Password changed successfully!")
        setCurrentPassword("")
        setNewPassword("")
        setConfirmPassword("")
        setTimeout(() => {
          setIsPasswordOpen(false)
          setSuccess("")
        }, 1500)
      }
    } catch (err) {
      setError("Failed to change password")
    } finally {
      setIsLoading(false)
    }
  }

  const hasAvatar =
    avatar && !avatar.includes("placeholder") && !avatar.includes("portrait") && !avatar.includes("avatar")

  return (
    <>
      <Card className="glass-card p-6">
        {/* Profile Header */}
        <div className="flex flex-col items-center mb-6">
          <div className="relative mb-4">
            <Avatar className="w-24 h-24 border-4 border-accent/30">
              {hasAvatar ? <AvatarImage src={avatar || "/placeholder.svg"} alt={name} /> : null}
              <AvatarFallback className="bg-secondary text-foreground text-2xl">
                {name.substring(0, 2).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            <div className="absolute -bottom-1 -right-1 bg-accent rounded-full p-1">
              <BadgeCheck className="w-5 h-5 text-accent-foreground" />
            </div>
          </div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-medium text-accent bg-accent/20 px-2 py-0.5 rounded-full">
              Verified {role}
            </span>
          </div>
          <h2 className="text-xl font-bold text-foreground">{name}</h2>
          <p className="text-sm text-muted-foreground">{email}</p>
        </div>

        {/* Profile Details */}
        <div className="space-y-4 mb-6">
          <div className="flex justify-between items-center py-2 border-b border-border/50">
            <span className="text-sm text-muted-foreground">Role</span>
            <span className="flex items-center gap-2 text-sm font-medium text-foreground">
              <Shield className="w-4 h-4 text-accent" />
              {role}
            </span>
          </div>
          {universityName && (
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-muted-foreground">University</span>
              <span className="text-sm font-medium text-foreground">{universityName}</span>
            </div>
          )}
          {universityId && (
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-muted-foreground">University ID</span>
              <span className="text-sm font-medium text-foreground">{universityId}</span>
            </div>
          )}
          {department && (
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-muted-foreground">Department</span>
              <span className="text-sm font-medium text-foreground">{department}</span>
            </div>
          )}
          {yearLevel && (
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-muted-foreground">Year Level</span>
              <span className="text-sm font-medium text-foreground">{yearLevel}</span>
            </div>
          )}
          {course && (
            <div className="flex justify-between items-center py-2 border-b border-border/50">
              <span className="text-sm text-muted-foreground">Course</span>
              <span className="text-sm font-medium text-foreground">{course}</span>
            </div>
          )}
          <div className="flex justify-between items-center py-2 border-b border-border/50">
            <span className="text-sm text-muted-foreground">Member Since</span>
            <span className="text-sm font-medium text-foreground">{joinDate}</span>
          </div>
          <div className="flex justify-between items-center py-2 border-b border-border/50">
            <span className="text-sm text-muted-foreground">Last Login</span>
            <span className="text-sm font-medium text-foreground">{lastLogin}</span>
          </div>
        </div>

        {/* Action Buttons - Now functional */}
        <div className="flex flex-col gap-3">
          <Button
            onClick={() => setIsEditOpen(true)}
            className="w-full bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <Edit className="w-4 h-4 mr-2" />
            Update Information
          </Button>
          <Button variant="outline" onClick={() => setIsPasswordOpen(true)} className="w-full bg-transparent">
            <KeyRound className="w-4 h-4 mr-2" />
            Change Password
          </Button>
        </div>
      </Card>

      {/* Edit Information Modal */}
      <Dialog open={isEditOpen} onOpenChange={setIsEditOpen}>
        <DialogContent className="glass-card border-border">
          <DialogHeader>
            <DialogTitle>Update Information</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleUpdateInfo} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Full Name</Label>
              <Input
                id="edit-name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="bg-input border-border"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-email">Email</Label>
              <Input
                id="edit-email"
                type="email"
                value={editEmail}
                onChange={(e) => setEditEmail(e.target.value)}
                className="bg-input border-border"
                required
              />
            </div>
            {error && <p className="text-destructive text-sm">{error}</p>}
            {success && <p className="text-green-500 text-sm">{success}</p>}
            <div className="flex gap-3 pt-2">
              <Button type="button" variant="outline" onClick={() => setIsEditOpen(false)} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" disabled={isLoading} className="flex-1">
                {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* Change Password Modal */}
      <Dialog open={isPasswordOpen} onOpenChange={setIsPasswordOpen}>
        <DialogContent className="glass-card border-border">
          <DialogHeader>
            <DialogTitle>Change Password</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleChangePassword} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="current-password">Current Password</Label>
              <Input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="bg-input border-border"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-password">New Password</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="bg-input border-border"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm New Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="bg-input border-border"
                required
              />
            </div>
            {error && <p className="text-destructive text-sm">{error}</p>}
            {success && <p className="text-green-500 text-sm">{success}</p>}
            <div className="flex gap-3 pt-2">
              <Button type="button" variant="outline" onClick={() => setIsPasswordOpen(false)} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" disabled={isLoading} className="flex-1">
                {isLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Change Password
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
