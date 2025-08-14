'use client';

import { useState } from 'react';
import { AgentAnswer } from '@dependency-canary/shared';

interface QAPanelProps {
  projectId: string;
  onAsk: (question: string) => Promise<AgentAnswer>;
}

export default function QAPanel({ projectId, onAsk }: QAPanelProps) {
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState<AgentAnswer | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const suggestedQuestions = [
    "What single upgrade removes the most critical CVEs?",
    "Which packages pose the highest supply chain risk?",
    "What are the most dangerous vulnerabilities in my direct dependencies?",
    "How can I reduce my attack surface with minimal changes?",
    "What abandoned packages should I replace first?",
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim() || loading) return;

    setLoading(true);
    setError(null);

    try {
      const result = await onAsk(question.trim());
      setAnswer(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get answer');
    } finally {
      setLoading(false);
    }
  };

  const askSuggestedQuestion = (suggestedQuestion: string) => {
    setQuestion(suggestedQuestion);
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4">Ask the Security Agent</h3>
      
      <form onSubmit={handleSubmit} className="mb-6">
        <div className="flex gap-2">
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about vulnerabilities, risks, or remediation strategies..."
            className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Asking...' : 'Ask'}
          </button>
        </div>
      </form>

      <div className="mb-6">
        <p className="text-sm text-gray-600 mb-2">Suggested questions:</p>
        <div className="flex flex-wrap gap-2">
          {suggestedQuestions.map((sq, index) => (
            <button
              key={index}
              onClick={() => askSuggestedQuestion(sq)}
              className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-1 rounded-full transition-colors"
              disabled={loading}
            >
              {sq}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {answer && (
        <div className="space-y-6">
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Answer:</h4>
            <div 
              className="prose prose-sm max-w-none text-gray-700"
              dangerouslySetInnerHTML={{ 
                __html: answer.answerMarkdown.replace(/\n/g, '<br>') 
              }}
            />
          </div>

          {answer.keyFindings.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">Key Findings:</h4>
              <ul className="space-y-2">
                {answer.keyFindings.map((finding, index) => (
                  <li key={index} className="flex items-start gap-2">
                    <span className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></span>
                    <div>
                      <span className="font-medium">{finding.nodeId}</span>
                      <p className="text-sm text-gray-600">{finding.reason}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {answer.remediationPlan.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-900 mb-2">Remediation Plan:</h4>
              <div className="space-y-4">
                {answer.remediationPlan.map((step, index) => (
                  <div key={index} className="border border-gray-200 rounded-md p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                        {step.impact} IMPACT
                      </span>
                      <span className="bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded">
                        {step.estimatedBreakage} BREAKAGE RISK
                      </span>
                    </div>
                    <h5 className="font-medium mb-2">{step.title}</h5>
                    <ul className="text-sm text-gray-600 mb-2 list-disc list-inside">
                      {step.actions.map((action, actionIndex) => (
                        <li key={actionIndex}>{action}</li>
                      ))}
                    </ul>
                    {step.affectedPackages.length > 0 && (
                      <p className="text-xs text-gray-500">
                        Affects: {step.affectedPackages.join(', ')}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {answer.citations.length > 0 && (
            <details className="text-sm">
              <summary className="cursor-pointer font-medium text-gray-700 hover:text-gray-900">
                Citations ({answer.citations.length})
              </summary>
              <ul className="mt-2 space-y-1">
                {answer.citations.map((citation, index) => (
                  <li key={index} className="flex items-center gap-2">
                    <span className="bg-gray-100 text-gray-600 text-xs px-2 py-0.5 rounded">
                      {citation.type}
                    </span>
                    <span className="text-gray-700">{citation.id}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </div>
  );
}