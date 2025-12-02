'use client'

import { Building2, Cog, FileText, Key, LayoutDashboard, Plus, Shield, Users, Wallet } from 'lucide-react'
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
}

export function AppSidebar({ currentAppId, currentAppName, isAdmin }: AppSidebarProps) {
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
          title: 'Wallets',
          url: `/apps/${currentAppId}/wallets`,
          icon: Wallet,
        },
        {
          title: 'Policies',
          url: `/apps/${currentAppId}/policies`,
          icon: Shield,
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
          title: 'Admin Dashboard',
          url: '/admin',
          icon: LayoutDashboard,
        },
        {
          title: 'All Apps',
          url: '/admin/apps',
          icon: Building2,
        },
        {
          title: 'System Health',
          url: '/admin/health',
          icon: Cog,
        },
        {
          title: 'Configuration',
          url: '/admin/config',
          icon: Cog,
        },
        {
          title: 'Global Audit',
          url: '/admin/audit',
          icon: FileText,
        },
      ]
    : []

  const isActive = (url: string, exact?: boolean) => {
    if (exact) {
      return pathname === url
    }
    return pathname.startsWith(url)
  }

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

        {/* Admin Navigation */}
        {isAdmin && adminNavItems.length > 0 && (
          <>
            <SidebarSeparator />
            <SidebarGroup>
              <SidebarGroupLabel>Admin</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {adminNavItems.map((item) => (
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
      </SidebarContent>
    </Sidebar>
  )
}
