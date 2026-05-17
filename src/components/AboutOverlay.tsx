'use client'

import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { ExternalLink } from '@/components/ExternalLink'

export function AboutOverlay({ className = '' }: { className?: string }) {
  const [isOpen, setIsOpen] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className={`inline-flex items-center rounded-full bg-slate-100 hover:bg-slate-200 px-3 py-1 text-xs font-medium text-slate-700 transition-colors ${className}`}
      >
        About
      </button>

      {mounted &&
        isOpen &&
        createPortal(
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-black/50 p-4"
          onClick={() => setIsOpen(false)}
        >
          <div
            className="bg-white rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-auto shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-8">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-3xl font-bold text-slate-900">Domain Shepherd</h2>
                  <p className="text-slate-600 mt-1">Track your domains. No account needed.</p>
                </div>
                <button
                  onClick={() => setIsOpen(false)}
                  className="text-slate-400 hover:text-slate-600 text-2xl"
                >
                  ×
                </button>
              </div>

              <div className="space-y-6 text-slate-600">
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 mb-2">What You Can Track</h3>
                  <div className="space-y-3">
                    <div>
                      <p className="font-medium text-slate-900">Response and target</p>
                      <p className="text-sm">
                        See whether a domain is OK, redirected, parked, unreachable, timed out, or missing DNS, plus
                        the resolved target URL.
                      </p>
                    </div>
                    <div>
                      <p className="font-medium text-slate-900">WHOIS context</p>
                      <p className="text-sm">
                        Surface registrar details, expiry dates, WHOIS status values, and readable explanations for
                        common ICANN and DENIC states.
                      </p>
                    </div>
                    <div>
                      <p className="font-medium text-slate-900">Operational workflow</p>
                      <p className="text-sm">
                        Bulk import domains, re-probe the full list, inspect details row by row, and copy the table
                        out as CSV when you need to report or hand off.
                      </p>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-slate-900 mb-2">Features</h3>
                  <ul className="space-y-2 text-sm">
                    <li className="flex gap-2">
                      <span>🌐</span>
                      <span>Track domain status and HTTP response codes</span>
                    </li>
                    <li className="flex gap-2">
                      <span>🧾</span>
                      <span>Inspect WHOIS data, registrar information, and nameservers</span>
                    </li>
                    <li className="flex gap-2">
                      <span>📤</span>
                      <span>Export your list as CSV for analysis or reporting</span>
                    </li>
                  </ul>
                </div>

                <p className="text-sm italic border-l-2 border-blue-200 pl-3">
                  All data is stored locally on your device. No accounts, no server-side storage.
                </p>

                <div>
                  <h3 className="text-lg font-semibold text-slate-900 mb-2">License</h3>
                  <p className="text-sm">Licensed under the MIT License.</p>
                  <p className="text-sm mt-1">
                    Copyright (c) 2026 Dirk Heider (
                    <ExternalLink
                      href="https://www.linkedin.com/in/dirkheider/"
                      rel="noreferrer"
                      className="text-blue-700 hover:text-blue-800 underline"
                    >
                      LinkedIn
                    </ExternalLink>
                    )
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </>
  )
}
