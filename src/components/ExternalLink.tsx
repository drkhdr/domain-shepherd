'use client'

import type { MouseEvent, ReactNode } from 'react'

interface ExternalLinkProps {
  href: string
  children: ReactNode
  className?: string
  title?: string
  rel?: string
}

function isTauriRuntime(): boolean {
  if (typeof window === 'undefined') return false
  return window.location.protocol === 'tauri:' || Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
}

export function ExternalLink({ href, children, className, title, rel }: ExternalLinkProps) {
  async function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    if (!isTauriRuntime()) {
      return
    }

    event.preventDefault()

    try {
      const { openUrl } = await import('@tauri-apps/plugin-opener')
      await openUrl(href)
    } catch (error) {
      console.error('Failed to open external URL:', error)
    }
  }

  return (
    <a
      href={href}
      target="_blank"
      rel={rel ?? 'noopener noreferrer'}
      className={className}
      title={title}
      onClick={handleClick}
    >
      {children}
    </a>
  )
}
