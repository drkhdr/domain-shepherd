import { NextRequest, NextResponse } from 'next/server'

import { runProbeBatch } from '@/lib/probe-runtime'
import { isProbeDomainInput, normalizeParkedPatterns } from '@/lib/probe'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'
// Keep probe results stable by running requests from a fixed Vercel region.
export const preferredRegion = 'fra1'

export async function POST(request: NextRequest) {
  try {
    const payload = (await request.json()) as { domains?: unknown; concurrency?: unknown; parkedPatterns?: unknown }
    const domains = Array.isArray(payload?.domains) ? payload.domains.filter(isProbeDomainInput) : []

    if (domains.length === 0) {
      return NextResponse.json(
        {
          error: 'Request body must include a non-empty domains array.',
          results: [],
        },
        { status: 400 }
      )
    }

    const results = await runProbeBatch(domains, payload?.concurrency, {
      parkedPatterns: normalizeParkedPatterns(payload?.parkedPatterns),
    })
    return NextResponse.json({ results })
  } catch (error) {
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Probe failed.',
        results: [],
      },
      { status: 500 }
    )
  }
}
