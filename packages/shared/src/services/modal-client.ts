import { ScanRequest, ScanResponse, EnrichResponse } from "../types/api";

export interface ModalClient {
  scan(request: ScanRequest): Promise<ScanResponse>;
  enrich(jobId: string): Promise<EnrichResponse>;
}

export class MockModalClient implements ModalClient {
  private jobs = new Map<string, EnrichResponse>();

  constructor() {
    this.initializeMockData();
  }

  async scan(request: ScanRequest): Promise<ScanResponse> {
    const jobId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return { jobId };
  }

  async enrich(jobId: string): Promise<EnrichResponse> {
    await new Promise(resolve => setTimeout(resolve, 200));
    
    if (!this.jobs.has(jobId)) {
      return this.getMockSBOM();
    }
    
    return this.jobs.get(jobId)!;
  }

  private getMockSBOM(): EnrichResponse {
    return {
      projectId: "mock_project_123",
      generatedAt: new Date().toISOString(),
      metadata: {
        languages: ["js", "py", "go"],
        services: ["web", "api", "worker"]
      },
      packages: [
        {
          name: "lodash",
          version: "4.17.19",
          eco: "npm",
          direct: true,
          serviceRefs: ["web"],
          license: "MIT",
          repoUrl: "https://github.com/lodash/lodash",
          stats: {
            lastCommit: "2024-05-01",
            weeklyDownloads: 10000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.02,
            newlyCreated: false,
            maintainerTrust: "medium"
          },
          vulns: [
            {
              id: "CVE-2020-8203",
              source: "NVD",
              cvss: 7.4,
              severity: "HIGH",
              published: "2020-07-10",
              summary: "Prototype pollution in lodash allows modification of object properties.",
              affectedRanges: ["<4.17.21"],
              exploits: [
                {
                  type: "POC",
                  url: "https://github.com/advisories/GHSA-p6mc-m468-83gw"
                }
              ],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-p6mc-m468-83gw"
                }
              ]
            }
          ],
          requires: [],
          requiredBy: [
            { name: "express", version: "4.18.2" }
          ]
        },
        {
          name: "axios",
          version: "0.21.1",
          eco: "npm",
          direct: true,
          serviceRefs: ["api"],
          license: "MIT",
          repoUrl: "https://github.com/axios/axios",
          stats: {
            lastCommit: "2024-03-15",
            weeklyDownloads: 45000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.01,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [
            {
              id: "CVE-2021-3749",
              source: "NVD",
              cvss: 9.1,
              severity: "CRITICAL",
              published: "2021-08-31",
              summary: "Server-side request forgery (SSRF) vulnerability in axios.",
              affectedRanges: ["<0.21.4"],
              exploits: [
                {
                  type: "EXPLOIT",
                  url: "https://security.snyk.io/vuln/SNYK-JS-AXIOS-1579269"
                }
              ],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-cph5-m8f7-6c5x"
                }
              ]
            }
          ],
          requires: [
            { name: "follow-redirects", version: "1.14.0" }
          ],
          requiredBy: []
        },
        {
          name: "follow-redirects",
          version: "1.14.0",
          eco: "npm",
          direct: false,
          serviceRefs: ["api"],
          license: "MIT",
          repoUrl: "https://github.com/follow-redirects/follow-redirects",
          stats: {
            lastCommit: "2024-01-20",
            weeklyDownloads: 40000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.05,
            newlyCreated: false,
            maintainerTrust: "medium"
          },
          vulns: [
            {
              id: "CVE-2022-0155",
              source: "NVD",
              cvss: 6.1,
              severity: "MEDIUM",
              published: "2022-01-10",
              summary: "Improper handling of URL redirect in follow-redirects.",
              affectedRanges: ["<1.14.7"],
              exploits: [],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-74fj-2j2h-c42q"
                }
              ]
            }
          ],
          requires: [],
          requiredBy: [
            { name: "axios", version: "0.21.1" }
          ]
        },
        {
          name: "express",
          version: "4.18.2",
          eco: "npm",
          direct: true,
          serviceRefs: ["web", "api"],
          license: "MIT",
          repoUrl: "https://github.com/expressjs/express",
          stats: {
            lastCommit: "2024-06-01",
            weeklyDownloads: 35000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.01,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [],
          requires: [
            { name: "lodash", version: "4.17.19" },
            { name: "cookie", version: "0.4.1" }
          ],
          requiredBy: []
        },
        {
          name: "cookie",
          version: "0.4.1",
          eco: "npm",
          direct: false,
          serviceRefs: ["web", "api"],
          license: "MIT",
          repoUrl: "https://github.com/jshttp/cookie",
          stats: {
            lastCommit: "2023-02-14",
            weeklyDownloads: 30000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.03,
            newlyCreated: false,
            maintainerTrust: "medium"
          },
          vulns: [],
          requires: [],
          requiredBy: [
            { name: "express", version: "4.18.2" }
          ]
        },
        {
          name: "requests",
          version: "2.25.1",
          eco: "pypi",
          direct: true,
          serviceRefs: ["worker"],
          license: "Apache-2.0",
          repoUrl: "https://github.com/psf/requests",
          stats: {
            lastCommit: "2023-12-01",
            weeklyDownloads: 50000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.01,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [
            {
              id: "CVE-2023-32681",
              source: "NVD",
              cvss: 6.1,
              severity: "MEDIUM",
              published: "2023-05-26",
              summary: "Requests library can leak proxy credentials in URLs.",
              affectedRanges: ["<2.31.0"],
              exploits: [],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-j8r2-6x86-q33q"
                }
              ]
            }
          ],
          requires: [
            { name: "urllib3", version: "1.26.5" },
            { name: "certifi", version: "2021.5.30" }
          ],
          requiredBy: []
        },
        {
          name: "urllib3",
          version: "1.26.5",
          eco: "pypi",
          direct: false,
          serviceRefs: ["worker"],
          license: "MIT",
          repoUrl: "https://github.com/urllib3/urllib3",
          stats: {
            lastCommit: "2024-04-15",
            weeklyDownloads: 45000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.02,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [
            {
              id: "CVE-2021-33503",
              source: "NVD",
              cvss: 7.5,
              severity: "HIGH",
              published: "2021-06-29",
              summary: "Catastrophic backtracking in URL parsing with urllib3.",
              affectedRanges: ["<1.26.6"],
              exploits: [
                {
                  type: "POC",
                  url: "https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg"
                }
              ],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-q2q7-5pp4-w6pg"
                }
              ]
            }
          ],
          requires: [],
          requiredBy: [
            { name: "requests", version: "2.25.1" }
          ]
        },
        {
          name: "certifi",
          version: "2021.5.30",
          eco: "pypi",
          direct: false,
          serviceRefs: ["worker"],
          license: "MPL-2.0",
          repoUrl: "https://github.com/certifi/python-certifi",
          stats: {
            lastCommit: "2023-11-01",
            weeklyDownloads: 50000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.01,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [],
          requires: [],
          requiredBy: [
            { name: "requests", version: "2.25.1" }
          ]
        }
      ],
      summary: {
        counts: {
          packages: 8,
          direct: 4,
          transitive: 4,
          vulns: 5,
          critical: 1,
          high: 2,
          medium: 2,
          low: 0
        },
        topRisks: [
          {
            package: "axios",
            version: "0.21.1",
            reason: "Critical SSRF vulnerability with public exploits",
            score: 0.92
          },
          {
            package: "urllib3",
            version: "1.26.5",
            reason: "High severity ReDoS vulnerability",
            score: 0.78
          },
          {
            package: "lodash",
            version: "4.17.19",
            reason: "Prototype pollution vulnerability with PoC exploit",
            score: 0.65
          }
        ]
      }
    };
  }

  private initializeMockData() {
  }
}

export class RealModalClient implements ModalClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async scan(request: ScanRequest): Promise<ScanResponse> {
    const response = await fetch(`${this.baseUrl}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new Error(`Scan failed: ${response.statusText}`);
    }

    return response.json() as Promise<ScanResponse>;
  }

  async enrich(jobId: string): Promise<EnrichResponse> {
    const response = await fetch(`${this.baseUrl}/enrich?jobId=${jobId}`);

    if (!response.ok) {
      throw new Error(`Enrich failed: ${response.statusText}`);
    }

    return response.json() as Promise<EnrichResponse>;
  }
}

export function createModalClient(): ModalClient {
  const baseUrl = process.env.MODAL_BASE_URL;
  const usePython = process.env.USE_PYTHON_BRIDGE === 'true' || process.env.NODE_ENV === 'development';
  
  // Prioritize Python bridge for real GitHub analysis
  if (usePython) {
    try {
      const { PythonModalClient } = require('./python-modal-client');
      console.log('Using Python bridge for real GitHub repository analysis');
      return new PythonModalClient();
    } catch (error) {
      console.log('Python bridge not available, falling back to mock client:', error instanceof Error ? error.message : String(error));
      return new MockModalClient();
    }
  }
  
  // Use real Modal client if base URL is provided
  if (baseUrl) {
    return new RealModalClient(baseUrl);
  }
  
  // Fallback to mock client
  console.log('No Python bridge or Modal URL configured, using mock client');
  return new MockModalClient();
}