import { NextRequest, NextResponse } from 'next/server'

import { lookupWhois } from '@/lib/probe-runtime'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'
export const preferredRegion = 'fra1'

export async function POST(request: NextRequest) {
  try {
    const payload = (await request.json()) as { domain?: unknown }
    const domain = typeof payload?.domain === 'string' ? payload.domain : ''

    if (!domain.trim()) {
      return NextResponse.json(
        {
          error: 'Request body must include a non-empty domain string.',
        },
        { status: 400 }
      )
    }

    const result = await lookupWhois(domain)
    return NextResponse.json(result)
  } catch (error) {
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'WHOIS lookup failed.',
      },
      { status: 500 }
    )
  }
}
