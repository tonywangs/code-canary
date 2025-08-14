import { VectorStore, VectorDocument, VectorSearchResult, VectorStoreQuery } from "@dependency-canary/shared";

export class PineconeVectorStore implements VectorStore {
  constructor(private apiKey: string, private indexName: string) {
  }

  async addDocuments(documents: VectorDocument[]): Promise<void> {
    throw new Error("Pinecone integration not implemented yet");
  }

  async search(query: VectorStoreQuery): Promise<VectorSearchResult[]> {
    throw new Error("Pinecone integration not implemented yet");
  }

  async clear(): Promise<void> {
    throw new Error("Pinecone integration not implemented yet");
  }
}