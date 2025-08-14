export interface VectorDocument {
  id: string;
  content: string;
  embedding?: number[];
  metadata: Record<string, any>;
}

export interface VectorSearchResult {
  document: VectorDocument;
  score: number;
}

export interface VectorStoreQuery {
  query: string;
  k?: number;
  filter?: Record<string, any>;
}

export interface VectorStore {
  addDocuments(documents: VectorDocument[]): Promise<void>;
  search(query: VectorStoreQuery): Promise<VectorSearchResult[]>;
  clear(): Promise<void>;
}

export interface Embedder {
  embed(text: string): Promise<number[]>;
  embedBatch(texts: string[]): Promise<number[][]>;
}

export interface AgentContext {
  packages: any[];
  vulnerabilities: any[];
  services: string[];
  relatedDocuments: VectorDocument[];
}