import { NextRequest, NextResponse } from 'next/server';
import { createModalClient } from '@dependency-canary/shared';
import { 
  createVectorStore, 
  createEmbedder, 
  SBOMProcessor, 
  SecurityAgent 
} from '@dependency-canary/agent';
import { corsResponse } from '@/lib/cors';

const agentInstance = new SecurityAgent(createVectorStore());

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

    // Skip expensive operations in development for faster testing
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
      
      await agentInstance.indexSBOM(sbom);
    } else {
      console.log('Skipping expensive operations for faster development testing');
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