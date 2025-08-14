import { Embedder } from "@dependency-canary/shared";

export class MockEmbedder implements Embedder {
  private dimension: number;

  constructor(dimension: number = 1536) {
    this.dimension = dimension;
  }

  async embed(text: string): Promise<number[]> {
    const seed = this.hashString(text);
    return this.generateConsistentVector(seed);
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    return Promise.all(texts.map(text => this.embed(text)));
  }

  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash);
  }

  private generateConsistentVector(seed: number): number[] {
    const vector: number[] = [];
    let rng = seed;
    
    for (let i = 0; i < this.dimension; i++) {
      rng = (rng * 1103515245 + 12345) & 0x7fffffff;
      vector.push((rng / 0x7fffffff - 0.5) * 2);
    }
    
    const magnitude = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    return vector.map(val => val / magnitude);
  }
}