import { NextRequest, NextResponse } from 'next/server';
import { AskRequest } from '@dependency-canary/shared';
import { corsResponse } from '@/lib/cors';
import { agentService } from '@/lib/agent-service';

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
    const body = await request.json() as AskRequest;
    
    if (!body.projectId || !body.question) {
      return corsResponse(
        { error: 'Missing required fields: projectId, question' },
        400
      );
    }

    const answer = await agentService.ask(body.projectId, body.question);
    
    return corsResponse(answer);
  } catch (error) {
    console.error('Ask API error:', error);
    return corsResponse(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      500
    );
  }
}