'use client'

import { Cog, Database, Key, Server, Shield } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'

import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'

// These would typically come from environment variables or a config API
const defaultConfig = {
  execution_backend: 'kms',
  kms_key_id: process.env.NEXT_PUBLIC_KMS_KEY_ID || '',
  rpc_endpoint: process.env.NEXT_PUBLIC_RPC_ENDPOINT || '',
  auth_issuer: process.env.NEXT_PUBLIC_AUTH_ISSUER || '',
  default_rate_limit: 100,
}

export default function AdminConfigPage() {
  const [config, setConfig] = useState(defaultConfig)
  const [isSaving, setIsSaving] = useState(false)

  const handleSave = async () => {
    setIsSaving(true)
    // In a real implementation, this would call an API to save config
    await new Promise((resolve) => setTimeout(resolve, 1000))
    toast.success('Configuration saved (demo only - changes are not persisted)')
    setIsSaving(false)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description="System-wide configuration settings for the wallet infrastructure"
        actions={
          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving ? 'Saving...' : 'Save Changes'}
          </Button>
        }
      />

      {/* Warning Banner */}
      <Card className="border-yellow-500/50 bg-yellow-500/10">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Shield className="h-5 w-5 text-yellow-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-yellow-700 dark:text-yellow-400">Configuration Management</p>
              <p className="text-sm text-muted-foreground mt-1">
                Changes to these settings affect all applications and wallets. Most configuration is managed through
                environment variables and requires a server restart to take effect.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Execution Backend */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            <CardTitle>Execution Backend</CardTitle>
          </div>
          <CardDescription>Configure the key management and signing backend</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="execution-backend">Backend Type</Label>
              <Select
                value={config.execution_backend}
                onValueChange={(value) => setConfig({ ...config, execution_backend: value })}
              >
                <SelectTrigger id="execution-backend">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="kms">KMS (Key Management Service)</SelectItem>
                  <SelectItem value="tee">TEE (Trusted Execution Environment)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                KMS uses cloud key management, TEE uses hardware security modules
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="kms-key-id">KMS Key ID</Label>
              <Input
                id="kms-key-id"
                value={config.kms_key_id}
                onChange={(e) => setConfig({ ...config, kms_key_id: e.target.value })}
                placeholder="arn:aws:kms:..."
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground">Master key ID for encrypting wallet shares</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* RPC Configuration */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            <CardTitle>Blockchain RPC</CardTitle>
          </div>
          <CardDescription>Configure blockchain network endpoints</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="rpc-endpoint">Default RPC Endpoint</Label>
            <Input
              id="rpc-endpoint"
              value={config.rpc_endpoint}
              onChange={(e) => setConfig({ ...config, rpc_endpoint: e.target.value })}
              placeholder="https://mainnet.infura.io/v3/..."
              className="font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground">
              Default EVM RPC endpoint for transaction submission (Infura, Alchemy, etc.)
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Authentication */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            <CardTitle>Authentication</CardTitle>
          </div>
          <CardDescription>Configure authentication providers for the wallet API</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="auth-issuer">Default Auth Issuer</Label>
            <Input
              id="auth-issuer"
              value={config.auth_issuer}
              onChange={(e) => setConfig({ ...config, auth_issuer: e.target.value })}
              placeholder="https://accounts.google.com"
              className="font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground">Default OIDC/JWT issuer for validating access tokens</p>
          </div>
        </CardContent>
      </Card>

      {/* Rate Limiting */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Cog className="h-5 w-5" />
            <CardTitle>Rate Limiting</CardTitle>
          </div>
          <CardDescription>Configure API rate limits</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="rate-limit">Default QPS Limit</Label>
              <Input
                id="rate-limit"
                type="number"
                value={config.default_rate_limit}
                onChange={(e) => setConfig({ ...config, default_rate_limit: Number.parseInt(e.target.value, 10) })}
              />
              <p className="text-xs text-muted-foreground">Default queries per second limit for new apps</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Environment Variables Reference */}
      <Card>
        <CardHeader>
          <CardTitle>Environment Variables</CardTitle>
          <CardDescription>Required environment variables for the wallet backend</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { name: 'POSTGRES_DSN', description: 'PostgreSQL connection string', required: true },
              { name: 'EXECUTION_BACKEND', description: 'kms or tee', required: false },
              { name: 'KMS_KEY_ID', description: 'Master key ID for KMS backend', required: true },
              { name: 'RPC_ENDPOINT', description: 'EVM RPC endpoint', required: true },
              { name: 'AUTH_KIND', description: 'oidc or jwt', required: false },
              { name: 'AUTH_ISSUER', description: 'JWT/OIDC issuer URL', required: true },
              { name: 'AUTH_AUDIENCE', description: 'JWT audience', required: false },
              { name: 'AUTH_JWKS_URI', description: 'JWKS URI for key verification', required: false },
              { name: 'PORT', description: 'HTTP server port (default: 8080)', required: false },
            ].map((env) => (
              <div key={env.name} className="flex items-center justify-between py-2">
                <div className="flex items-center gap-3">
                  <code className="bg-muted px-2 py-1 rounded text-sm font-mono">{env.name}</code>
                  <span className="text-sm text-muted-foreground">{env.description}</span>
                </div>
                <Badge variant={env.required ? 'default' : 'secondary'}>{env.required ? 'Required' : 'Optional'}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Separator />

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={isSaving}>
          {isSaving ? 'Saving...' : 'Save Changes'}
        </Button>
      </div>
    </div>
  )
}
