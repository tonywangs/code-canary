import './globals.css';
import { Inter } from 'next/font/google';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'Dependency Canary',
  description: 'AI-powered dependency vulnerability analysis and supply chain security',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <nav className="bg-gray-900 text-white p-4">
          <div className="container mx-auto flex items-center justify-between">
            <h1 className="text-xl font-bold">🐦 Dependency Canary</h1>
            <p className="text-sm text-gray-300">AI-powered security analysis</p>
          </div>
        </nav>
        <main className="container mx-auto px-4 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}