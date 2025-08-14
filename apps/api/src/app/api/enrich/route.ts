import { NextRequest, NextResponse } from 'next/server';
import { createModalClient } from '@dependency-canary/shared';
import { 
  createVectorStore, 
  createEmbedder, 
  SBOMProcessor
} from '@dependency-canary/agent';
import { corsResponse } from '@/lib/cors';
import { agentService } from '@/lib/agent-service';

export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const jobId = searchParams.get('jobId');

    if (!jobId) {
      return corsResponse(
        { error: 'Missing jobId parameter' },
        400
      );
    }

    const client = createModalClient();
    const sbom = await client.enrich(jobId);

    // Always index the SBOM for the agent to work properly
    console.log('Indexing SBOM for agent access...');
    await agentService.indexSBOM(sbom);
    
    // Skip expensive embedding operations in development for faster testing
    const skipExpensiveOps = process.env.SKIP_EMBEDDINGS === 'true' || process.env.NODE_ENV === 'development';
    
    if (!skipExpensiveOps) {
      console.log('Running full processing with embeddings...');
      const processor = new SBOMProcessor();
      const documents = processor.processToDocuments(sbom);
      
      const embedder = createEmbedder();
      for (const doc of documents) {
        if (!doc.embedding) {
          doc.embedding = await embedder.embed(doc.content);
        }
      }

      const vectorStore = createVectorStore();
      await vectorStore.addDocuments(documents);
    } else {
      console.log('Skipping expensive embedding operations for faster development testing');
    }

    return corsResponse(sbom);
  } catch (error) {
    console.error('Enrich API error:', error);
    return corsResponse(
      { error: 'Internal server error' },
      500
    );
  }
}