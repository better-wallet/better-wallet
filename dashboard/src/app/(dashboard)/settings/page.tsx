import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">Configure your Better Wallet instance</p>
      </div>

      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <CardTitle>API Configuration</CardTitle>
            <CardDescription>Configure connection to Better Wallet API</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="apiUrl">API URL</Label>
              <Input id="apiUrl" placeholder="http://localhost:8080" defaultValue="http://localhost:8080" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="appId">App ID</Label>
              <Input id="appId" placeholder="Your app ID" />
            </div>
            <Button>Save Configuration</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Authentication</CardTitle>
            <CardDescription>Configure authentication provider settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="authKind">Auth Kind</Label>
              <Input id="authKind" defaultValue="oidc" disabled />
            </div>
            <div className="space-y-2">
              <Label htmlFor="issuer">Issuer URL</Label>
              <Input id="issuer" placeholder="https://your-issuer.com" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="audience">Audience</Label>
              <Input id="audience" placeholder="your-audience" />
            </div>
            <Button>Update Auth Settings</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Execution Backend</CardTitle>
            <CardDescription>Configure key execution backend</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Current Backend</Label>
              <p className="text-sm text-muted-foreground">KMS</p>
            </div>
            <Separator />
            <div className="space-y-2">
              <Label htmlFor="kmsKeyId">KMS Key ID</Label>
              <Input id="kmsKeyId" placeholder="alias/your-key" />
            </div>
            <Button>Update Backend Settings</Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
