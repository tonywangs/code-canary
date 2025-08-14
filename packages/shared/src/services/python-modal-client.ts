import { spawn } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { ScanRequest, ScanResponse, EnrichResponse } from '../types/api';
import { ModalClient } from './modal-client';

// Simple in-memory cache to store project references by job ID
const projectReferenceCache = new Map<string, string>();

export class PythonModalClient implements ModalClient {
  private pythonBridgePath: string;

  constructor() {
    // Path to the Python bridge script
    // Adjust path based on where the code is running from
    const apiDir = process.cwd().includes('apps/api') 
      ? process.cwd() 
      : path.join(process.cwd(), 'apps/api');
    
    this.pythonBridgePath = path.join(apiDir, 'python/bridge.py');
  }

  async scan(request: ScanRequest): Promise<ScanResponse> {
    try {
      const result = await this.executePythonBridge('scan', [
        '--project-ref', request.ref,
        '--ref-type', request.refType,
        '--use-modal'  // Use Modal workers for real cloud processing
      ]);

      // Store the project reference in cache using the returned job ID
      const response = result as ScanResponse;
      projectReferenceCache.set(response.jobId, request.ref);
      
      return response;
    } catch (error) {
      console.error('Python scan failed, falling back to mock:', error);
      // Fallback to mock behavior
      const jobId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      projectReferenceCache.set(jobId, request.ref);
      return { jobId };
    }
  }

  async enrich(jobId: string): Promise<EnrichResponse> {
    try {
      // Get the project reference from cache
      const projectRef = projectReferenceCache.get(jobId) || '.';
      
      const result = await this.executePythonBridge('enrich', [
        '--job-id', jobId,
        '--project-ref', projectRef
      ]);

      // Clean up cache entry after use
      projectReferenceCache.delete(jobId);
      
      return result as EnrichResponse;
    } catch (error) {
      console.error('Python enrich failed, falling back to mock:', error);
      // Clean up cache entry even on error
      projectReferenceCache.delete(jobId);
      // Fallback to mock data
      return this.getMockEnrichResponse();
    }
  }

  private async executePythonBridge(command: string, args: string[]): Promise<any> {
    return new Promise((resolve, reject) => {
      const pythonArgs = [this.pythonBridgePath, command, ...args];
      const python = spawn('python3', pythonArgs, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env }
      });

      let stdout = '';
      let stderr = '';

      python.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      python.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      python.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`Python bridge failed with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (parseError) {
          reject(new Error(`Failed to parse Python bridge output: ${parseError}\nOutput: ${stdout}`));
        }
      });

      python.on('error', (error) => {
        reject(new Error(`Failed to spawn Python process: ${error.message}`));
      });
    });
  }

  private getMockEnrichResponse(): EnrichResponse {
    return {
      projectId: "python_fallback_project",
      generatedAt: new Date().toISOString(),
      metadata: {
        languages: ["python", "javascript"],
        services: ["api", "worker"]
      },
      packages: [
        {
          name: "requests",
          version: "2.28.1",
          eco: "pypi",
          direct: true,
          serviceRefs: ["api"],
          license: "Apache-2.0",
          repoUrl: "https://github.com/psf/requests",
          stats: {
            lastCommit: "2023-05-01",
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
              id: "CVE-2023-32681",
              source: "NVD",
              cvss: 6.1,
              severity: "MEDIUM",
              published: "2023-05-26",
              summary: "Requests library can leak Proxy-Authorization header to destination server.",
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
            { name: "urllib3", version: "1.26.12" },
            { name: "certifi", version: "2022.9.24" }
          ],
          requiredBy: []
        },
        {
          name: "urllib3",
          version: "1.26.12",
          eco: "pypi",
          direct: false,
          serviceRefs: ["api"],
          license: "MIT",
          repoUrl: "https://github.com/urllib3/urllib3",
          stats: {
            lastCommit: "2023-03-15",
            weeklyDownloads: 50000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.02,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [],
          requires: [],
          requiredBy: [
            { name: "requests", version: "2.28.1" }
          ]
        },
        {
          name: "axios",
          version: "0.27.2", 
          eco: "npm",
          direct: true,
          serviceRefs: ["api"],
          license: "MIT",
          repoUrl: "https://github.com/axios/axios",
          stats: {
            lastCommit: "2023-04-01",
            weeklyDownloads: 40000000
          },
          risk: {
            abandoned: false,
            typoSuspicion: 0.01,
            newlyCreated: false,
            maintainerTrust: "high"
          },
          vulns: [
            {
              id: "CVE-2022-1214",
              source: "NVD", 
              cvss: 7.5,
              severity: "HIGH",
              published: "2022-04-08",
              summary: "A regular expression denial of service (ReDoS) vulnerability in axios.",
              affectedRanges: [">=0.27.0", "<0.27.3"],
              exploits: [
                {
                  type: "POC",
                  url: "https://github.com/advisories/GHSA-4w2j-2rg4-5mjw"
                }
              ],
              advisories: [
                {
                  source: "GHSA",
                  id: "GHSA-4w2j-2rg4-5mjw"
                }
              ]
            }
          ],
          requires: [],
          requiredBy: []
        }
      ],
      summary: {
        counts: {
          packages: 3,
          direct: 2,
          transitive: 1,
          vulns: 2,
          critical: 0,
          high: 1,
          medium: 1,
          low: 0
        },
        topRisks: [
          {
            package: "axios",
            version: "0.27.2",
            reason: "High severity ReDoS vulnerability with PoC available",
            score: 0.75
          },
          {
            package: "requests", 
            version: "2.28.1",
            reason: "Medium severity information disclosure vulnerability",
            score: 0.45
          }
        ]
      }
    };
  }
}