import { BookOpen } from "lucide-react"

interface LogoProps {
  className?: string
  size?: "sm" | "md" | "lg"
}

export function Logo({ className, size = "md" }: LogoProps) {
  const sizes = {
    sm: { icon: 20, text: "text-lg" },
    md: { icon: 24, text: "text-xl" },
    lg: { icon: 32, text: "text-2xl" },
  }

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="relative">
        <BookOpen size={sizes[size].icon} className="text-primary" strokeWidth={2.5} />
      </div>
      <span className={`font-semibold text-foreground ${sizes[size].text}`}>LibraLink</span>
    </div>
  )
}
