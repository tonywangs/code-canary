import Database from "better-sqlite3";
import { VectorStore, VectorDocument, VectorSearchResult, VectorStoreQuery } from "@dependency-canary/shared";

export class SQLiteVectorStore implements VectorStore {
  private db: Database.Database;

  constructor(dbPath: string = ":memory:") {
    this.db = new Database(dbPath);
    this.initialize();
  }

  private initialize() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        content TEXT NOT NULL,
        metadata TEXT NOT NULL,
        embedding BLOB
      );
      
      CREATE INDEX IF NOT EXISTS idx_id ON documents(id);
    `);
  }

  async addDocuments(documents: VectorDocument[]): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO documents (id, content, metadata, embedding)
      VALUES (?, ?, ?, ?)
    `);

    const transaction = this.db.transaction((docs: VectorDocument[]) => {
      for (const doc of docs) {
        const embeddingBuffer = doc.embedding 
          ? Buffer.from(new Float64Array(doc.embedding).buffer)
          : null;
        
        stmt.run(
          doc.id,
          doc.content,
          JSON.stringify(doc.metadata),
          embeddingBuffer
        );
      }
    });

    transaction(documents);
  }

  async search(query: VectorStoreQuery): Promise<VectorSearchResult[]> {
    let sql = "SELECT id, content, metadata, embedding FROM documents";
    const params: any[] = [];
    
    if (query.filter) {
      const conditions: string[] = [];
      
      for (const [key, value] of Object.entries(query.filter)) {
        conditions.push(`json_extract(metadata, '$.${key}') = ?`);
        params.push(value);
      }
      
      if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(" AND ")}`;
      }
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);

    const results: VectorSearchResult[] = rows.map((row: any) => {
      let embedding: number[] | undefined;
      
      if (row.embedding) {
        const buffer = Buffer.from(row.embedding);
        embedding = Array.from(new Float64Array(buffer.buffer));
      }

      return {
        document: {
          id: row.id,
          content: row.content,
          metadata: JSON.parse(row.metadata),
          embedding,
        },
        score: 1.0,
      };
    });

    if (query.k) {
      return results.slice(0, query.k);
    }

    return results;
  }

  async clear(): Promise<void> {
    this.db.exec("DELETE FROM documents");
  }

  close() {
    this.db.close();
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