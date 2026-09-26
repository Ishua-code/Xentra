'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { GitBranch, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { login } from '@/lib/api'

export default function LoginPage() {
  const router = useRouter()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      router.push('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0a0e17] p-4">
      <Card className="dashboard-card w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <div className="logo-mark mb-3">
            <GitBranch className="size-5" />
          </div>
          <CardTitle className="text-lg">Sign in to XENTRA</CardTitle>
          <p className="text-xs text-slate-500">Security operations dashboard</p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Username</label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                autoComplete="username"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400">Password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                required
              />
            </div>
            {error && <p className="text-xs text-red-400">{error}</p>}
            <Button type="submit" disabled={loading} className="mt-2 bg-blue-600 text-white hover:bg-blue-500">
              {loading ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
              Sign in
            </Button>
            <p className="mt-1 text-center text-[11px] text-slate-600">Demo credentials: admin / xentra123</p>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}