# 🐦 Dependency Canary

AI-powered dependency vulnerability analysis and supply chain security platform. Analyzes your project's entire dependency graph (SBOM) to flag vulnerabilities, supply-chain risks, and generate minimal patch plans.

Won 1st Place Overall + 2nd Place Modal Prize at the [AI Agent & Infra Hackathon](https://ai-agent-infra.devpost.com/) (by Lux Capital, Modal, Cognition, AWS, and Ramp)

Demo video link: https://youtu.be/eLHv1lriGms  
Devpost link: https://devpost.com/software/code-canary

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Modal/Mock    │
│  (Next.js)      │───▶│  API Routes     │───▶│   Services      │
│                 │    │                 │    │                 │
│ • Upload Form   │    │ • /api/scan     │    │ • SBOM Extract  │
│ • Results View  │    │ • /api/enrich   │    │ • Vuln Enrich   │
│ • Dep Graph     │    │ • /api/ask      │    │ • Multi-lang    │
│ • Q&A Panel     │    │ • /api/report   │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   AI Agent      │
                       │                 │
                       │ • RAG Pipeline  │
                       │ • Vector Store  │
                       │ • LLM Reasoning │
                       │ • Patch Plans   │
                       └─────────────────┘
```

## 📦 Monorepo Structure

```
dependency-canary/
├── apps/
│   ├── web/                 # Next.js frontend (port 3000)
│   └── api/                 # API backend (port 3001)
├── packages/
│   ├── shared/              # TypeScript types & API clients
│   └── agent/               # RAG agent & vector processing
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- pnpm 8+
- Optional: OpenAI API key for production embeddings

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd dependency-canary

# Install all dependencies
pnpm install

# Build shared packages
pnpm -r build
```

### Development Setup

```bash
# Seed the system with mock data
pnpm seed:mock

# Start both frontend and API in development mode
pnpm dev

# Or start individually:
pnpm --filter @dependency-canary/web dev     # Frontend: http://localhost:3000
pnpm --filter @dependency-canary/api dev     # API: http://localhost:3001
```

### Environment Variables

Create `.env.local` files in both `apps/web` and `apps/api`:

```bash
# Optional: Real Modal endpoints
MODAL_BASE_URL=https://your-modal-deployment.com

# Optional: OpenAI for embeddings (defaults to mock)
OPENAI_API_KEY=sk-...

# Optional: Vector store configuration
VECTOR_STORE_TYPE=memory|sqlite|pinecone
SQLITE_DB_PATH=./vector-store.db
PINECONE_API_KEY=...
PINECONE_INDEX=...
```

**Default Behavior (No Env Vars):**
- Uses mock Modal client with realistic test data
- Uses mock embedder with deterministic vectors
- Uses in-memory vector store

## 🎯 Usage Workflow

### 1. Upload Project
Navigate to http://localhost:3000 and either:
- Enter a GitHub repository URL
- Upload a ZIP file URL 
- Specify a container image

### 2. Scan & Analysis
The system will:
- Generate SBOM (Software Bill of Materials)
- Enrich with CVE data from NVD, OSV, GHSA
- Analyze supply chain risks
- Index into vector database

### 3. Interactive Analysis
- **KPI Dashboard**: View vulnerability counts, risk scores
- **Dependency Graph**: Interactive visualization with severity color-coding
- **AI Q&A**: Ask natural language questions about vulnerabilities
- **Remediation Plans**: Get prioritized upgrade recommendations

### 4. Generate Reports
Download comprehensive PDF or Markdown reports with:
- Executive summary
- Detailed vulnerability analysis
- Remediation roadmap
- Package inventory

## 🤖 Sample Questions for AI Agent

Try asking these questions in the Q&A panel:

- "What single upgrade removes the most critical CVEs?"
- "Which packages pose the highest supply chain risk?"
- "What are the most dangerous vulnerabilities in my direct dependencies?"
- "How can I reduce my attack surface with minimal changes?"
- "What abandoned packages should I replace first?"
- "Which vulnerabilities have public exploits available?"

## 🧪 Testing

```bash
# Run all tests
pnpm test

# Run smoke tests specifically
pnpm --filter @dependency-canary/agent test

# Test with verbose output
pnpm test -- --reporter=verbose
```

### Smoke Test Coverage
- ✅ Mock SBOM generation with realistic vulnerabilities
- ✅ Vector store operations and filtering
- ✅ Agent Q&A functionality with remediation plans
- ✅ End-to-end workflow validation
- ✅ Embedding consistency and document processing

## 📊 Mock Data Details

The mock service provides a realistic test dataset with:
- **8 packages** across npm, PyPI ecosystems
- **5 vulnerabilities** (1 Critical, 2 High, 2 Medium)
- **3 services** (web, api, worker)
- **Supply chain risks** (prototype pollution, SSRF, ReDoS)

Key test packages:
- `axios@0.21.1` - Critical SSRF vulnerability (CVE-2021-3749)
- `lodash@4.17.19` - Prototype pollution (CVE-2020-8203)  
- `urllib3@1.26.5` - ReDoS vulnerability (CVE-2021-33503)

## 🔧 Development

### Adding New Vector Stores

```typescript
// packages/agent/src/vector-stores/custom-store.ts
import { VectorStore, VectorDocument, VectorSearchResult } from '@dependency-canary/shared';

export class CustomVectorStore implements VectorStore {
  async addDocuments(documents: VectorDocument[]): Promise<void> {
    // Implementation
  }
  
  async search(query: VectorStoreQuery): Promise<VectorSearchResult[]> {
    // Implementation
  }
  
  async clear(): Promise<void> {
    // Implementation
  }
}
```

### Adding New Embedders

```typescript
// packages/agent/src/embedders/custom-embedder.ts
import { Embedder } from '@dependency-canary/shared';

export class CustomEmbedder implements Embedder {
  async embed(text: string): Promise<number[]> {
    // Implementation
  }
  
  async embedBatch(texts: string[]): Promise<number[][]> {
    // Implementation
  }
}
```

## 🔗 API Contracts

### Modal Integration Points

```typescript
// Scan endpoint
POST /api/scan
Body: { projectRef: string, refType: "git"|"zip"|"image", ref: string }
Response: { jobId: string }

// Enrich endpoint  
GET /api/enrich?jobId=<jobId>
Response: EnrichedSBOM (see types/sbom.ts)
```

### Internal API Routes

```typescript
// Ask the AI agent
POST /api/ask
Body: { projectId: string, question: string }
Response: AgentAnswer (see types/api.ts)

// Generate reports
GET /api/report?projectId=<id>&format=pdf|markdown
Response: PDF blob or Markdown text
```

## 📈 Performance Notes

- **Vector Store**: In-memory store for dev, SQLite/Pinecone for production
- **Embeddings**: ~1500 dimensions, cached per document
- **Agent Reasoning**: Context-aware RAG with metadata filtering
- **Report Generation**: Server-side PDF rendering with Puppeteer

## 🔒 Security Considerations

- Never logs or commits API keys
- Sanitizes user inputs in search queries  
- Validates SBOM schemas before processing
- Uses read-only vector operations in agent reasoning

## 🚢 Production Deployment

### Environment Setup
```bash
# Production build
pnpm build

# Set production environment variables
export MODAL_BASE_URL=https://your-modal-deployment.com
export OPENAI_API_KEY=sk-...
export VECTOR_STORE_TYPE=sqlite
export SQLITE_DB_PATH=/data/vector-store.db

# Start production servers
pnpm --filter @dependency-canary/web start
pnpm --filter @dependency-canary/api start
```

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN corepack enable pnpm && pnpm install --frozen-lockfile
RUN pnpm build
CMD ["pnpm", "dev"]
```

## 🤝 Integration with Real Modal Services

When your teammate's Modal services are ready:

1. Set `MODAL_BASE_URL` environment variable
2. The system automatically switches from mock to real client
3. No code changes needed - interface is identical

The Modal services should implement:
- `POST /scan` → `{ jobId }`
- `GET /enrich?jobId=...` → `EnrichedSBOM`

## 📋 Todo / Future Enhancements

- [ ] WebSocket support for real-time scan progress
- [ ] GitHub Actions integration for CI/CD scanning  
- [ ] SARIF output format support
- [ ] Multi-project comparison views
- [ ] Slack/Teams notifications for critical findings
- [ ] Custom risk scoring models
- [ ] Integration with dependency management tools

## 🐛 Troubleshooting

### Common Issues

**"No SBOM available" error:**
- Ensure you've run `pnpm seed:mock` 
- Check that both web and API servers are running

**Vector store errors:**
- Clear data: `rm -rf *.db` and re-run seed script
- Check filesystem permissions for SQLite

**PDF generation fails:**
- Install system dependencies: `apt-get install -y chromium-browser`
- For Docker: use `puppeteer/puppeteer:latest` base image

**Empty dependency graph:**
- Verify service filter selection
- Check browser console for JavaScript errors

## 🎉 Demo Walkthrough

1. **Start**: `pnpm dev` (both apps running)
2. **Seed**: `pnpm seed:mock` (populate with test data)  
3. **Upload**: Visit localhost:3000, paste `https://github.com/mock/repo`
4. **Scan**: Click "Start Security Scan" (uses mock data)
5. **Explore**: View KPIs, interact with dependency graph
6. **Ask**: "What single upgrade removes the most critical CVEs?"
7. **Report**: Download PDF with full analysis
8. **Test**: Run `pnpm test` to validate all components

---

Built with ❤️ for supply chain security. Questions? Check the code or run the smoke tests!
