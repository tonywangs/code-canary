import { Embedder } from "@dependency-canary/shared";
import { OpenAIEmbedder } from "./openai-embedder";
import { MockEmbedder } from "./mock-embedder";

export { OpenAIEmbedder } from "./openai-embedder";
export { MockEmbedder } from "./mock-embedder";

export function createEmbedder(): Embedder {
  const openaiKey = process.env.OPENAI_API_KEY;
  
  if (!openaiKey) {
    console.log("No OpenAI API key found, using mock embedder");
    return new MockEmbedder();
  }
  
  return new OpenAIEmbedder(openaiKey);
}