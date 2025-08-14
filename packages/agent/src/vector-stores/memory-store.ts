import { VectorStore, VectorDocument, VectorSearchResult, VectorStoreQuery } from "@dependency-canary/shared";

export class InMemoryVectorStore implements VectorStore {
  private documents: VectorDocument[] = [];

  async addDocuments(documents: VectorDocument[]): Promise<void> {
    for (const doc of documents) {
      const existingIndex = this.documents.findIndex(d => d.id === doc.id);
      if (existingIndex >= 0) {
        this.documents[existingIndex] = doc;
      } else {
        this.documents.push(doc);
      }
    }
  }

  async search(query: VectorStoreQuery): Promise<VectorSearchResult[]> {
    let filteredDocs = this.documents;

    if (query.filter) {
      filteredDocs = this.documents.filter(doc => {
        return Object.entries(query.filter!).every(([key, value]) => {
          return doc.metadata[key] === value;
        });
      });
    }

    const results: VectorSearchResult[] = filteredDocs.map(doc => ({
      document: doc,
      score: Math.random(),
    }));

    results.sort((a, b) => b.score - a.score);

    if (query.k) {
      return results.slice(0, query.k);
    }

    return results;
  }

  async clear(): Promise<void> {
    this.documents = [];
  }

  private cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;
    
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }
}