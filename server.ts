import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // AI Client - Lazy initialisation
  let ai: GoogleGenAI | null = null;
  function getAI() {
    if (!ai) {
      if (!process.env.GEMINI_API_KEY) {
        throw new Error('GEMINI_API_KEY is not set');
      }
      ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    }
    return ai;
  }

  // --- API Routes ---

  app.post('/api/audit', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
      // 1. Basic Recon: Try to fetch headers
      const fetchResponse = await fetch(url, { method: 'HEAD', timeout: 5000 }).catch(() => null);
      const headers: Record<string, string> = {};
      if (fetchResponse) {
        fetchResponse.headers.forEach((value, key) => {
          headers[key] = value;
        });
      }

      // 2. Use Gemini to "Audit" based on headers and common web patterns
      // This provides the "Smart" logic requested
      const genAI = getAI();
      const model = 'gemini-3-flash-preview';
      
      const prompt = `Perform a simulated security audit context analysis for the URL: ${url}. 
      Actual headers retrieved (if any): ${JSON.stringify(headers)}.
      
      Identify:
      - 2-4 subdomains that might exist (recon simulation).
      - 3-5 open ports typical for this type of service.
      - Vulnerability scan for missing headers (HSTS, CSP, X-Frame-Options, etc).
      - Locate 3-4 potential admin login pages.
      - A risk score out of 10.
      
      Return the output as internal JSON following this schema:
      {
        "subdomains": string[],
        "open_ports": string[],
        "vulnerabilities": Array<{ type: string, severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO', description: string, hint: string }>,
        "admin_paths": string[],
        "risk_score": string,
        "metrics": { findings: number, ports: number, reqSec: number },
        "logs": string[]
      }`;

      const response = await genAI.models.generateContent({
        model,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              subdomains: { type: Type.ARRAY, items: { type: Type.STRING } },
              open_ports: { type: Type.ARRAY, items: { type: Type.STRING } },
              vulnerabilities: { 
                type: Type.ARRAY, 
                items: { 
                  type: Type.OBJECT, 
                  properties: {
                    type: { type: Type.STRING },
                    severity: { type: Type.STRING },
                    description: { type: Type.STRING },
                    hint: { type: Type.STRING }
                  }
                } 
              },
              admin_paths: { type: Type.ARRAY, items: { type: Type.STRING } },
              risk_score: { type: Type.STRING },
              metrics: {
                type: Type.OBJECT,
                properties: {
                  findings: { type: Type.NUMBER },
                  ports: { type: Type.NUMBER },
                  reqSec: { type: Type.NUMBER }
                }
              },
              logs: { type: Type.ARRAY, items: { type: Type.STRING } }
            }
          }
        }
      });

      const result = JSON.parse(response.text);
      res.json(result);

    } catch (error) {
      console.error('Audit Error:', error);
      res.status(500).json({ error: 'Failed to perform audit' });
    }
  });

  // --- Vite Integration ---

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
}

startServer();
