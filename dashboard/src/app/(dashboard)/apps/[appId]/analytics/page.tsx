'use client'

import { BarChart3, RefreshCw, TrendingUp, Users, Wallet } from 'lucide-react'
import { useParams } from 'next/navigation'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { ErrorState } from '@/components/data/error-state'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'
import { useState } from 'react'

const COLORS = ['#2563eb', '#16a34a', '#dc2626', '#ca8a04', '#9333ea', '#0891b2']

function formatDate(dateStr: string) {
  const date = new Date(dateStr)
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

function formatVolume(wei: number) {
  const eth = wei / 1e18
  if (eth >= 1000) return `${(eth / 1000).toFixed(1)}k ETH`
  if (eth >= 1) return `${eth.toFixed(2)} ETH`
  return `${eth.toFixed(4)} ETH`
}

export default function AnalyticsPage() {
  const params = useParams()
  const appId = params.appId as string
  const [days, setDays] = useState(30)

  const { data: stats, isLoading: statsLoading } = trpc.backend.stats.useQuery({ appId })
  const {
    data: analytics,
    isLoading: analyticsLoading,
    error,
    refetch,
  } = trpc.backend.analytics.useQuery({ appId, days })

  const isLoading = statsLoading || analyticsLoading

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Analytics" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  // Fill in missing dates for charts
  const fillDates = (data: { date: string; count: number }[]) => {
    const dateMap = new Map(data.map((d) => [d.date, d.count]))
    const result = []
    const today = new Date()
    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(today)
      date.setDate(date.getDate() - i)
      const dateStr = date.toISOString().split('T')[0]
      result.push({ date: dateStr, count: dateMap.get(dateStr) || 0 })
    }
    return result
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Analytics"
        description="Monitor your app's usage and performance"
        actions={
          <div className="flex gap-2">
            <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
              <SelectTrigger className="w-[130px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7">Last 7 days</SelectItem>
                <SelectItem value="30">Last 30 days</SelectItem>
                <SelectItem value="90">Last 90 days</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        }
      />

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{stats?.users_count.toLocaleString()}</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Wallets</CardTitle>
            <Wallet className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{stats?.wallets_count.toLocaleString()}</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Transactions</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{stats?.transactions_count.toLocaleString()}</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Policies</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <div className="text-2xl font-bold">{stats?.policies_count.toLocaleString()}</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 1 */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Users Over Time */}
        <Card>
          <CardHeader>
            <CardTitle>User Registrations</CardTitle>
            <CardDescription>New users per day</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={fillDates(analytics?.dailyUsers || [])}>
                  <defs>
                    <linearGradient id="colorUsers" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" tickFormatter={formatDate} className="text-xs" />
                  <YAxis allowDecimals={false} className="text-xs" />
                  <Tooltip
                    labelFormatter={formatDate}
                    contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#2563eb" fillOpacity={1} fill="url(#colorUsers)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Wallets Over Time */}
        <Card>
          <CardHeader>
            <CardTitle>Wallet Creations</CardTitle>
            <CardDescription>New wallets per day</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={fillDates(analytics?.dailyWallets || [])}>
                  <defs>
                    <linearGradient id="colorWallets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#16a34a" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#16a34a" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" tickFormatter={formatDate} className="text-xs" />
                  <YAxis allowDecimals={false} className="text-xs" />
                  <Tooltip
                    labelFormatter={formatDate}
                    contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#16a34a" fillOpacity={1} fill="url(#colorWallets)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2 */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Transaction Volume */}
        <Card>
          <CardHeader>
            <CardTitle>Transaction Volume</CardTitle>
            <CardDescription>Confirmed transaction value per day (ETH)</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={analytics?.dailyVolume || []}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" tickFormatter={formatDate} className="text-xs" />
                  <YAxis tickFormatter={(v) => formatVolume(v)} className="text-xs" />
                  <Tooltip
                    labelFormatter={formatDate}
                    formatter={(value: number) => [formatVolume(value), 'Volume']}
                    contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }}
                  />
                  <Bar dataKey="volume" fill="#9333ea" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Wallets by Chain */}
        <Card>
          <CardHeader>
            <CardTitle>Wallets by Chain</CardTitle>
            <CardDescription>Distribution of wallets across chains</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : analytics?.walletsByChain && analytics.walletsByChain.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={analytics.walletsByChain}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name || ''} (${((percent || 0) * 100).toFixed(0)}%)`}
                    outerRadius={100}
                    dataKey="count"
                    nameKey="chainType"
                  >
                    {analytics.walletsByChain.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">No wallet data</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 3 */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Transaction Status */}
        <Card>
          <CardHeader>
            <CardTitle>Transaction Status</CardTitle>
            <CardDescription>Distribution by status</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : analytics?.transactionsByStatus && analytics.transactionsByStatus.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={analytics.transactionsByStatus} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis type="number" className="text-xs" />
                  <YAxis dataKey="status" type="category" className="text-xs" width={80} />
                  <Tooltip contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {analytics.transactionsByStatus.map((entry, index) => {
                      const colors: Record<string, string> = {
                        confirmed: '#16a34a',
                        pending: '#ca8a04',
                        submitted: '#2563eb',
                        failed: '#dc2626',
                      }
                      return <Cell key={`cell-${index}`} fill={colors[entry.status] || '#6b7280'} />
                    })}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">No transaction data</div>
            )}
          </CardContent>
        </Card>

        {/* Policy Decisions */}
        <Card>
          <CardHeader>
            <CardTitle>Policy Decisions</CardTitle>
            <CardDescription>Allow vs Deny over the period</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[300px]" />
            ) : analytics?.policyDecisions && analytics.policyDecisions.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={analytics.policyDecisions}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name || ''} (${((percent || 0) * 100).toFixed(0)}%)`}
                    outerRadius={100}
                    dataKey="count"
                    nameKey="result"
                  >
                    {analytics.policyDecisions.map((entry, index) => {
                      const colors: Record<string, string> = {
                        allow: '#16a34a',
                        deny: '#dc2626',
                      }
                      return <Cell key={`cell-${index}`} fill={colors[entry.result] || COLORS[index % COLORS.length]} />
                    })}
                  </Pie>
                  <Tooltip contentStyle={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[300px] flex items-center justify-center text-muted-foreground">No policy decision data</div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
