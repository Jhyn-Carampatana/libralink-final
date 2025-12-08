import { Card } from "@/components/ui/card"
import { CheckCircle } from "lucide-react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import type { User } from "@/lib/db"

interface ProfileCardProps {
  user: User & { year_level?: string; course?: string }
}

export function ProfileCard({ user }: ProfileCardProps) {
  const hasAvatar =
    user.avatar_url &&
    !user.avatar_url.includes("placeholder") &&
    !user.avatar_url.includes("portrait")

  return (
    <div className="space-y-6">
      {/* Digital ID Card (Now Main Profile Card) */}
      <Card className="bg-gradient-to-br from-black/80 to-gray-900 border border-border rounded-xl overflow-hidden p-6 shadow-xl">

        {/* University Header */}
        <div className="flex items-center justify-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold">
            UC
          </div>
          <span className="text-white font-semibold tracking-wide">University of Cebu</span>
        </div>

        {/* Motto Removed, Cleaner Look */}
        <p className="text-blue-300 text-xs text-center italic mb-4">
          Identification Card
        </p>

        <div className="flex gap-4">
          {/* Profile Photo */}
          <div className="w-24 h-28 bg-gradient-to-b from-secondary to-muted rounded-lg flex items-center justify-center overflow-hidden">
            {hasAvatar ? (
              <img
                src={user.avatar_url! || "/placeholder.svg"}
                alt="ID Photo"
                className="w-full h-full object-cover"
              />
            ) : (
              <span className="text-white text-2xl font-bold">
                {user.full_name.substring(0, 2).toUpperCase()}
              </span>
            )}
          </div>

          {/* ID Details */}
          <div className="flex-1 space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-blue-200">ID No.</span>
              <span className="text-white font-mono">
                {user.university_id || "N/A"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-blue-200">Full Name</span>
              <span className="text-white">{user.full_name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-blue-200">Year Level</span>
              <span className="text-white">{(user as any).year_level || "N/A"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-blue-200">Course</span>
              <span className="text-white truncate max-w-[100px]">
                {(user as any).course || "N/A"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-blue-200">Contact</span>
              <span className="text-white truncate max-w-[200px]">
                {user.phone || user.email}
              </span>
            </div>
          </div>
        </div>

        {/* Verified Badge */}
        {user.email_verified && (
          <div className="flex items-center justify-center gap-1.5 mt-4">
            <CheckCircle className="w-4 h-4 text-green-500 fill-green-500" />
            <span className="text-xs text-green-500 font-medium">
              UC Verified Student
            </span>
          </div>
        )}
      </Card>
    </div>
  )
}
