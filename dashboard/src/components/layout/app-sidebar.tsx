'use client'

import { ArrowLeftRight, BarChart3, Building2, Cog, FileText, FlaskConical, Key, LayoutDashboard, Plus, Shield, UserCircle, Users, Wallet } from 'lucide-react'
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
  currentAppId?: string
  currentAppName?: string
  isAdmin?: boolean
  isAdminRoute?: boolean
}

export function AppSidebar({ currentAppId, currentAppName, isAdmin, isAdminRoute }: AppSidebarProps) {
  const pathname = usePathname()

  // Global nav items (when no app is selected)
  const globalNavItems = [
    {
      title: 'Apps',
      url: '/apps',
      icon: Building2,
    },
  ]

  // App-specific nav items
  const appNavItems = currentAppId
    ? [
        {
          title: 'Overview',
          url: `/apps/${currentAppId}`,
          icon: LayoutDashboard,
          exact: true,
        },
        {
          title: 'Analytics',
          url: `/apps/${currentAppId}/analytics`,
          icon: BarChart3,
        },
        {
          title: 'Wallets',
          url: `/apps/${currentAppId}/wallets`,
          icon: Wallet,
        },
        {
          title: 'Transactions',
          url: `/apps/${currentAppId}/transactions`,
          icon: ArrowLeftRight,
        },
        {
          title: 'Policies',
          url: `/apps/${currentAppId}/policies`,
          icon: Shield,
        },
        {
          title: 'Policy Tester',
          url: `/apps/${currentAppId}/policies/test`,
          icon: FlaskConical,
        },
        {
          title: 'Auth Keys',
          url: `/apps/${currentAppId}/keys`,
          icon: Key,
        },
        {
          title: 'Condition Sets',
          url: `/apps/${currentAppId}/condition-sets`,
          icon: FileText,
        },
        {
          title: 'Users',
          url: `/apps/${currentAppId}/users`,
          icon: UserCircle,
        },
      ]
    : []

  const appManagementItems = currentAppId
    ? [
        {
          title: 'Members',
          url: `/apps/${currentAppId}/members`,
          icon: Users,
        },
        {
          title: 'API Secrets',
          url: `/apps/${currentAppId}/secrets`,
          icon: Key,
        },
        {
          title: 'Settings',
          url: `/apps/${currentAppId}/settings`,
          icon: Cog,
        },
        {
          title: 'Audit Log',
          url: `/apps/${currentAppId}/audit`,
          icon: FileText,
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
          title: 'All Apps',
          url: '/admin/apps',
          icon: Building2,
          exact: false,
        },
        {
          title: 'System Health',
          url: '/admin/health',
          icon: Cog,
          exact: false,
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
            <span className="font-semibold text-lg">Better Wallet</span>
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
        <Link href="/apps" className="flex items-center gap-2">
          <Wallet className="h-6 w-6" />
          <span className="font-semibold text-lg">Better Wallet</span>
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
                  <Link href="/apps/new" className="text-muted-foreground hover:text-foreground">
                    <Plus className="h-4 w-4" />
                    <span>Create App</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Current App Navigation */}
        {currentAppId && (
          <>
            <SidebarSeparator />
            <SidebarGroup>
              <SidebarGroupLabel className="truncate" title={currentAppName}>
                {currentAppName || 'Current App'}
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {appNavItems.map((item) => (
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

            <SidebarGroup>
              <SidebarGroupLabel>App Management</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {appManagementItems.map((item) => (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton asChild isActive={isActive(item.url)}>
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
