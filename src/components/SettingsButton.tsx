'use client'

import { SETTINGS_OPEN_EVENT } from '@/lib/app-config'

export function SettingsButton({ className = '' }: { className?: string }) {
  function openSettings() {
    if (typeof window === 'undefined') return
    window.dispatchEvent(new CustomEvent(SETTINGS_OPEN_EVENT))
  }

  return (
    <button
      type="button"
      onClick={openSettings}
      className={`inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-200 ${className}`}
    >
      Settings
    </button>
  )
}
