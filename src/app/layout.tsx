import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import Link from 'next/link'
import { AboutOverlay } from '@/components/AboutOverlay'
import { ExternalLink } from '@/components/ExternalLink'
import { SettingsButton } from '@/components/SettingsButton'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Domain Shepherd',
  description: 'Track your domains. No account needed.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <header className="sticky top-0 z-40 border-b border-slate-200 bg-white/90 backdrop-blur">
          <div className="px-4 md:px-6">
            <div className="mx-auto flex h-14 w-full max-w-[var(--app-content-max-width)] items-center">
              <h1 className="text-base font-semibold tracking-tight text-slate-900">
                <span className="inline-flex items-center gap-2">
                  <ExternalLink
                    href="https://www.linkedin.com/in/dirkheider/"
                    rel="noreferrer"
                    title="Dirk Heider LinkedIn"
                  >
                    <img
                      src="/dh%20blue.svg"
                      alt="Domain Shepherd logo"
                      width={22}
                      height={22}
                      className="h-[22px] w-[22px]"
                    />
                  </ExternalLink>
                  <Link href="/">Domain Shepherd</Link>
                </span>
              </h1>
              <div className="ml-auto flex items-center gap-2">
                <SettingsButton />
                <AboutOverlay />
              </div>
            </div>
          </div>
        </header>
        {children}
      </body>
    </html>
  )
}
