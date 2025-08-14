/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ['@dependency-canary/shared', '@dependency-canary/agent'],
};

module.exports = nextConfig;