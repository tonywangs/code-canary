'use client';

import { useState } from 'react';
import { ScanRequest } from '@dependency-canary/shared';

interface UploadFormProps {
  onSubmit: (request: ScanRequest) => void;
  loading?: boolean;
}

export default function UploadForm({ onSubmit, loading = false }: UploadFormProps) {
  const [formData, setFormData] = useState({
    refType: 'git' as 'git' | 'zip' | 'image',
    ref: '',
    projectRef: 'user-input',
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.ref.trim()) return;

    onSubmit({
      projectRef: formData.projectRef,
      refType: formData.refType,
      ref: formData.ref.trim(),
    });
  };

  const handleRefTypeChange = (refType: 'git' | 'zip' | 'image') => {
    setFormData(prev => ({ ...prev, refType }));
  };

  const getPlaceholder = () => {
    switch (formData.refType) {
      case 'git':
        return 'https://github.com/user/repo';
      case 'zip':
        return 'https://example.com/project.zip';
      case 'image':
        return 'nginx:latest or docker.io/library/nginx:latest';
      default:
        return '';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 mb-8">
      <h2 className="text-2xl font-bold mb-4">Scan Your Project</h2>
      <p className="text-gray-600 mb-6">
        Analyze your project's dependency graph for vulnerabilities and supply chain risks.
      </p>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Project Type
          </label>
          <div className="flex gap-4">
            {(['git', 'zip', 'image'] as const).map((type) => (
              <button
                key={type}
                type="button"
                onClick={() => handleRefTypeChange(type)}
                className={`px-4 py-2 rounded-md border transition-colors ${
                  formData.refType === type
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                }`}
              >
                {type.charAt(0).toUpperCase() + type.slice(1)} Repository
              </button>
            ))}
          </div>
        </div>

        <div>
          <label htmlFor="ref" className="block text-sm font-medium text-gray-700 mb-2">
            {formData.refType === 'git' ? 'Repository URL' : 
             formData.refType === 'zip' ? 'ZIP File URL' : 'Container Image'}
          </label>
          <input
            type="text"
            id="ref"
            value={formData.ref}
            onChange={(e) => setFormData(prev => ({ ...prev, ref: e.target.value }))}
            placeholder={getPlaceholder()}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            disabled={loading}
          />
        </div>

        <button
          type="submit"
          disabled={loading || !formData.ref.trim()}
          className="w-full bg-blue-600 text-white py-3 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Scanning...' : 'Start Security Scan'}
        </button>
      </form>
    </div>
  );
}