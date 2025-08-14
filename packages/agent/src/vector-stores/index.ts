import { VectorStore } from "@dependency-canary/shared";
import { InMemoryVectorStore } from "./memory-store";
import { SQLiteVectorStore } from "./sqlite-store";
import { PineconeVectorStore } from "./pinecone-store";

export { InMemoryVectorStore } from "./memory-store";
export { SQLiteVectorStore } from "./sqlite-store";
export { PineconeVectorStore } from "./pinecone-store";

export function createVectorStore(): VectorStore {
  const storeType = process.env.VECTOR_STORE_TYPE || "memory";
  
  switch (storeType) {
    case "sqlite":
      return new SQLiteVectorStore(process.env.SQLITE_DB_PATH || "./vector-store.db");
    case "pinecone":
      if (!process.env.PINECONE_API_KEY || !process.env.PINECONE_INDEX) {
        throw new Error("Pinecone configuration missing");
      }
      return new PineconeVectorStore(process.env.PINECONE_API_KEY, process.env.PINECONE_INDEX);
    case "memory":
    default:
      return new InMemoryVectorStore();
  }
}