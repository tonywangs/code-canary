import { NextRequest, NextResponse } from 'next/server';

export function corsHeaders(origin?: string) {
  return {
    'Access-Control-Allow-Origin': origin || 'http://localhost:3000',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}

export function handleCors(request: NextRequest, response: NextResponse) {
  const origin = request.headers.get('origin');
  const headers = corsHeaders(origin || undefined);
  
  Object.entries(headers).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  
  return response;
}

export function corsResponse(data: any, status: number = 200, origin?: string) {
  const response = NextResponse.json(data, { status });
  const headers = corsHeaders(origin);
  
  Object.entries(headers).forEach(([key, value]) => {
    response.headers.set(key, value);
  });
  
  return response;
}