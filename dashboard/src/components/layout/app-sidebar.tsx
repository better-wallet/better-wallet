'use client'

import { ArrowLeftRight, Cog, FileText, Key, LayoutDashboard, Plus, Shield, Wallet } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarSeparator,
} from '@/components/ui/sidebar'

interface AppSidebarProps {
  currentWalletId?: string
  currentWalletName?: string
  isAdmin?: boolean
  isAdminRoute?: boolean
}

export function AppSidebar({ currentWalletId, currentWalletName, isAdmin, isAdminRoute }: AppSidebarProps) {
  const pathname = usePathname()

  // Global nav items
  const globalNavItems = [
    {
      title: 'Wallets',
      url: '/wallets',
      icon: Wallet,
    },
    {
      title: 'API Keys',
      url: '/api-keys',
      icon: Key,
    },
    {
      title: 'Audit Log',
      url: '/audit',
      icon: FileText,
    },
  ]

  // Wallet-specific nav items
  const walletNavItems = currentWalletId
    ? [
        {
          title: 'Overview',
          url: `/wallets/${currentWalletId}`,
          icon: LayoutDashboard,
          exact: true,
        },
        {
          title: 'Credentials',
          url: `/wallets/${currentWalletId}/credentials`,
          icon: Shield,
        },
        {
          title: 'Transactions',
          url: `/wallets/${currentWalletId}/transactions`,
          icon: ArrowLeftRight,
        },
        {
          title: 'Settings',
          url: `/wallets/${currentWalletId}/settings`,
          icon: Cog,
        },
      ]
    : []

  // Admin nav items
  const adminNavItems = isAdmin
    ? [
        {
          title: 'Dashboard',
          url: '/admin',
          icon: LayoutDashboard,
          exact: true,
        },
        {
          title: 'Configuration',
          url: '/admin/config',
          icon: Cog,
          exact: false,
        },
      ]
    : []

  const isActive = (url: string, exact?: boolean) => {
    if (exact) {
      return pathname === url
    }
    return pathname.startsWith(url)
  }

  // When on admin routes, show only admin navigation
  if (isAdminRoute && isAdmin) {
    return (
      <Sidebar>
        <SidebarHeader className="border-b px-6 py-4">
          <Link href="/admin" className="flex items-center gap-2">
            <Wallet className="h-6 w-6" />
            <span className="font-semibold text-lg">Agent Wallet</span>
          </Link>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Administration</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {adminNavItems.map((item) => (
                  <SidebarMenuItem key={item.title}>
                    <SidebarMenuButton asChild isActive={isActive(item.url, item.exact)}>
                      <Link href={item.url}>
                        <item.icon className="h-4 w-4" />
                        <span>{item.title}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
    )
  }

  // Normal user view
  return (
    <Sidebar>
      <SidebarHeader className="border-b px-6 py-4">
        <Link href="/wallets" className="flex items-center gap-2">
          <Wallet className="h-6 w-6" />
          <span className="font-semibold text-lg">Agent Wallet</span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        {/* Global Navigation */}
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {globalNavItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild isActive={isActive(item.url)}>
                    <Link href={item.url}>
                      <item.icon className="h-4 w-4" />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
              <SidebarMenuItem>
                <SidebarMenuButton asChild>
                  <Link href="/wallets/new" className="text-muted-foreground hover:text-foreground">
                    <Plus className="h-4 w-4" />
                    <span>Create Wallet</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Current Wallet Navigation */}
        {currentWalletId && (
          <>
            <SidebarSeparator />
            <SidebarGroup>
              <SidebarGroupLabel className="truncate" title={currentWalletName}>
                {currentWalletName || 'Current Wallet'}
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {walletNavItems.map((item) => (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton asChild isActive={isActive(item.url, item.exact)}>
                        <Link href={item.url}>
                          <item.icon className="h-4 w-4" />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}

        {/* Admin Link - only show if user has admin privileges */}
        {isAdmin && (
          <>
            <SidebarSeparator />
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <SidebarMenuButton asChild>
                      <Link href="/admin" className="text-muted-foreground hover:text-foreground">
                        <LayoutDashboard className="h-4 w-4" />
                        <span>Admin Console</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}
      </SidebarContent>
    </Sidebar>
  )
}
