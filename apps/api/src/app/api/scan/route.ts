import { NextRequest, NextResponse } from 'next/server';
import { ScanRequest, createModalClient } from '@dependency-canary/shared';
import { corsResponse } from '@/lib/cors';

export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json() as ScanRequest;
    
    if (!body.ref || !body.refType || !body.projectRef) {
      return corsResponse(
        { error: 'Missing required fields: ref, refType, projectRef' },
        400
      );
    }

    const client = createModalClient();
    const result = await client.scan(body);

    return corsResponse(result);
  } catch (error) {
    console.error('Scan API error:', error);
    return corsResponse(
      { error: 'Internal server error' },
      500
    );
  }
}