"use client"

import { useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Search, Clock, User } from "lucide-react"
import type { SystemLogWithUser } from "@/lib/db"

interface AdminLogsClientProps {
  initialLogs: SystemLogWithUser[]
}

export function AdminLogsClient({ initialLogs }: AdminLogsClientProps) {
  const [logs] = useState(initialLogs)
  const [searchQuery, setSearchQuery] = useState("")
  const [userFilter, setUserFilter] = useState("all")
  const [actionFilter, setActionFilter] = useState("all")

  const uniqueUsers = [...new Set(logs.map((log) => (log.user as any)?.full_name).filter(Boolean))]
  const uniqueActions = [...new Set(logs.map((log) => log.action))]

  const filteredLogs = logs.filter((log) => {
    const userName = (log.user as any)?.full_name || ""
    const matchesSearch =
      userName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesUser = userFilter === "all" || userName === userFilter
    const matchesAction = actionFilter === "all" || log.action === actionFilter
    return matchesSearch && matchesUser && matchesAction
  })

  const getActionColor = (action: string) => {
    if (action.includes("add") || action.includes("create") || action.includes("approve")) {
      return "bg-green-500/20 text-green-400"
    }
    if (action.includes("delete") || action.includes("suspend") || action.includes("decline")) {
      return "bg-red-500/20 text-red-400"
    }
    if (action.includes("update") || action.includes("change")) {
      return "bg-blue-500/20 text-blue-400"
    }
    if (action.includes("return") || action.includes("paid")) {
      return "bg-cyan-500/20 text-cyan-400"
    }
    return "bg-gray-500/20 text-gray-400"
  }

  return (
    <main className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground mb-1">System Logs</h1>
        <p className="text-muted-foreground">Monitor all system activities and user actions</p>
      </div>

      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground w-5 h-5" />
          <Input
            placeholder="Search logs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 bg-input border-border"
          />
        </div>
        <Select value={userFilter} onValueChange={setUserFilter}>
          <SelectTrigger className="w-48 bg-input border-border">
            <SelectValue placeholder="Filter by user" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Users</SelectItem>
            {uniqueUsers.map((user) => (
              <SelectItem key={user} value={user}>
                {user}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={actionFilter} onValueChange={setActionFilter}>
          <SelectTrigger className="w-48 bg-input border-border">
            <SelectValue placeholder="Filter by action" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actions</SelectItem>
            {uniqueActions.map((action) => (
              <SelectItem key={action} value={action}>
                {action}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left p-4 text-sm font-medium text-muted-foreground">User</th>
                <th className="text-left p-4 text-sm font-medium text-muted-foreground">Action</th>
                <th className="text-left p-4 text-sm font-medium text-muted-foreground">Entity</th>
                <th className="text-left p-4 text-sm font-medium text-muted-foreground">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-muted-foreground" />
                        <span className="text-foreground font-medium">{(log.user as any)?.full_name || "System"}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getActionColor(log.action)}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="text-muted-foreground">{log.entity_type || "-"}</span>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Clock className="w-4 h-4" />
                        <span className="text-sm">{new Date(log.created_at).toLocaleString()}</span>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-muted-foreground">
                    No logs found matching your filters
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="mt-4 text-sm text-muted-foreground">
        Showing {filteredLogs.length} of {logs.length} log entries
      </div>
    </main>
  )
}
