import React, { useState } from 'react';
import { Shield, Search, Lock, BookOpen, CheckCircle2, AlertTriangle, ShieldCheck, Terminal, Loader2, Globe, Server, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// --- Types ---

interface Vulnerability {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  description: string;
  hint: string;
}

interface AuditResult {
  subdomains: string[];
  open_ports: string[];
  vulnerabilities: Vulnerability[];
  admin_paths: string[];
  risk_score: string;
  metrics: {
    findings: number;
    ports: number;
    reqSec: number;
  };
  logs: string[];
}

// --- Components ---

const Card = ({ children, className = "" }: { children: React.ReactNode; className?: string }) => (
  <div className={`bg-slate-900/50 border border-slate-800 rounded shadow-inner p-6 ${className}`}>
    {children}
  </div>
);

const Badge = ({ children, variant = 'default' }: { children: React.ReactNode; variant?: 'default' | 'warning' | 'success' | 'info' | 'critical' }) => {
  const styles = {
    default: 'bg-slate-800 text-slate-400 border border-slate-700',
    warning: 'bg-amber-500/10 text-amber-500 border border-amber-500/30',
    success: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30',
    info: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
    critical: 'bg-red-500/10 text-red-500 border border-red-500/30',
  };
  return <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-tighter ${styles[variant]}`}>{children}</span>;
};

// --- Sections ---

const ReconSection = ({ data }: { data: AuditResult | null }) => (
  <div className="space-y-6">
    <header className="border-b border-emerald-500/30 pb-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <Search className="w-5 h-5 text-emerald-400" />
        <h2 className="text-xl font-bold tracking-tight text-emerald-400 uppercase">Phase_01: Reconnaissance</h2>
      </div>
      <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-mono">Infrastructure Surface Mapping</p>
    </header>
    
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-2">
          <Globe className="w-4 h-4 text-emerald-400" />
          <h3 className="text-emerald-400 font-mono text-xs font-bold uppercase tracking-widest">Subdomain Mapping</h3>
        </div>
        <div className="grid grid-cols-1 gap-2">
          {data?.subdomains.map((sub, i) => (
            <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-800/30 p-2 rounded border border-slate-700/50">
              <CheckCircle2 className="w-3 h-3 text-emerald-500" />
              {sub}
            </div>
          )) || <p className="text-xs text-slate-500 italic">No subdomains mapped. Initialize scan.</p>}
        </div>
      </Card>
      <Card>
        <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-2">
          <Server className="w-4 h-4 text-blue-400" />
          <h3 className="text-blue-400 font-mono text-xs font-bold uppercase tracking-widest">Port Fingerprinting</h3>
        </div>
        <div className="flex flex-wrap gap-2">
          {data?.open_ports.map((port, i) => (
            <Badge key={i} variant="info">{port}</Badge>
          )) || <p className="text-xs text-slate-500 italic">No open ports identified.</p>}
        </div>
      </Card>
    </div>
    
    <div className="bg-black border border-slate-800 p-4 rounded font-mono text-sm overflow-hidden relative">
      <div className="absolute top-0 right-0 p-2">
        <span className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="text-[10px] text-emerald-500/70 uppercase font-bold">Strategy_Engine</span>
        </span>
      </div>
      <div className="space-y-2 text-emerald-500/80 text-xs">
        <p><span className="text-slate-600">[HINT]</span> Hardening recommendation: Disable unnecessary services and closed ports.</p>
        {data?.vulnerabilities.at(0) && (
          <p><span className="text-slate-600 font-bold underline">REC:</span> {data.vulnerabilities[0].hint}</p>
        )}
      </div>
    </div>
  </div>
);

const VulnerabilitySection = ({ data }: { data: AuditResult | null }) => (
  <div className="space-y-6">
    <header className="border-b border-emerald-500/30 pb-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <ShieldCheck className="w-5 h-5 text-emerald-400" />
        <h2 className="text-xl font-bold tracking-tight text-emerald-400 uppercase">Phase_02: Vulnerability_Analysis</h2>
      </div>
      <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-mono">Static and Dynamic Flaw Detection</p>
    </header>
    
    <div className="space-y-4">
      {data?.vulnerabilities.map((vuln, i) => (
        <Card key={i} className={`border-l-2 ${vuln.severity === 'CRITICAL' ? 'border-l-red-500' : vuln.severity === 'HIGH' ? 'border-l-amber-500' : 'border-l-blue-500'}`}>
          <div className="flex justify-between items-start mb-2">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-tight">{vuln.type}</h3>
            <Badge variant={vuln.severity === 'CRITICAL' ? 'critical' : vuln.severity === 'HIGH' ? 'warning' : 'info'}>
              {vuln.severity}
            </Badge>
          </div>
          <p className="text-xs text-slate-400 mb-4 leading-relaxed font-sans">{vuln.description}</p>
          <div className="bg-black p-3 rounded font-mono text-xs text-emerald-500/80 border border-slate-800">
            <span className="text-slate-600 uppercase font-bold text-[9px] mr-2 tracking-tighter underline">PATCH:</span>
            {vuln.hint}
          </div>
        </Card>
      )) || <p className="text-center py-12 text-slate-600 font-mono text-xs italic">Initialize audit to begin analysis...</p>}
    </div>
  </div>
);

const AdminSection = ({ data }: { data: AuditResult | null }) => (
  <div className="space-y-6">
    <header className="border-b border-emerald-500/30 pb-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <Lock className="w-5 h-5 text-emerald-400" />
        <h2 className="text-xl font-bold tracking-tight text-emerald-400 uppercase">Phase_03: Admin_Panel_Hardening</h2>
      </div>
      <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-mono">Privileged Interface Security</p>
    </header>
    
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 border-b border-slate-800 pb-2">Exposed Interfaces</h3>
        <ul className="text-xs space-y-2 font-mono text-slate-400">
           {data?.admin_paths.map((path, i) => (
             <li key={i} className="flex items-center justify-between">
               <span className="flex items-center gap-2">
                 <span className="w-1 h-1 bg-red-500 rounded-full"></span> {path}
               </span>
               <span className="text-[9px] text-red-500/60 uppercase font-bold">Vulnerable</span>
             </li>
           )) || <li className="text-slate-600 italic">No paths identified.</li>}
        </ul>
      </Card>
      <Card>
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 border-b border-slate-800 pb-2">Defense Protocols</h3>
        <ul className="text-xs space-y-2 font-mono text-emerald-500/70">
           <li className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span> MFA Enforcement</li>
           <li className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span> IP-Based Access Control</li>
           <li className="flex items-center gap-2"><span className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></span> Brute Force Lockout</li>
        </ul>
      </Card>
    </div>

    <Card className="bg-black/60 font-mono text-xs border border-slate-800 p-4">
      <h3 className="text-slate-500 uppercase tracking-widest mb-3 font-bold">Logic_Audit_Trail</h3>
      <div className="text-emerald-500/80 space-y-2 max-h-48 overflow-y-auto custom-scrollbar">
        {data?.logs.map((log, i) => (
          <p key={i} className="text-xs">{log}</p>
        )) || <p className="text-slate-600">Waiting for trace packets...</p>}
      </div>
    </Card>
  </div>
);

const RemediationSection = () => (
  <div className="space-y-6">
    <header className="border-b border-emerald-500/30 pb-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <Terminal className="w-5 h-5 text-emerald-400" />
        <h2 className="text-xl font-bold tracking-tight text-emerald-400 uppercase">Phase_04: Mitigation_Protocol</h2>
      </div>
      <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-mono">Corrective Action and Verification</p>
    </header>
    
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      <Card className="md:col-span-2">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 border-b border-slate-800 pb-2">Resolution Pipeline</h3>
        <div className="space-y-6 mt-4">
          <div className="flex gap-4">
            <span className="text-emerald-500 font-mono font-bold">01_</span>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Validation of Findings</h4>
              <p className="text-xs text-slate-500 font-sans leading-relaxed">Confirm the vulnerability exists via manual PoC attempts in a clean environment.</p>
            </div>
          </div>
          <div className="flex gap-4">
            <span className="text-emerald-500 font-mono font-bold">02_</span>
            <div>
              <h4 className="text-sm font-bold text-slate-200">CVSS V3.1 Score</h4>
              <p className="text-xs text-slate-500 font-sans leading-relaxed">Map the threat against a standard impact matrix to define patch priority.</p>
            </div>
          </div>
          <div className="flex gap-4">
            <span className="text-emerald-500 font-mono font-bold">03_</span>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Regression Audit</h4>
              <p className="text-xs text-slate-500 font-sans leading-relaxed">Perform a follow-up scan after fixes are deployed to ensure zero partial-fixes.</p>
            </div>
          </div>
        </div>
      </Card>
      
      <div className="space-y-4">
        <Card className="bg-emerald-500/5 border border-emerald-500/20">
          <h3 className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest mb-4">Recommended Toolset</h3>
          <ul className="text-xs space-y-3 font-mono text-slate-400">
            <li className="flex items-center gap-2 hover:text-emerald-400 transition-colors">
              <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div> OWASP ZAP
            </li>
            <li className="flex items-center gap-2 hover:text-emerald-400 transition-colors">
              <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div> Burp Suite Pro
            </li>
            <li className="flex items-center gap-2 hover:text-emerald-400 transition-colors">
              <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div> Nessus Expert
            </li>
          </ul>
        </Card>
      </div>
    </div>
  </div>
);

const AuditGuideSection = () => (
  <div className="space-y-6">
    <header className="border-b border-emerald-500/30 pb-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <Terminal className="w-5 h-5 text-emerald-400" />
        <h2 className="text-xl font-bold tracking-tight text-emerald-400 uppercase">AUDIT_OPERATIONS.md</h2>
      </div>
      <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-mono">Standard Operating Procedure_v2.0</p>
    </header>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card className="bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2 mb-4">
          <Badge variant="info">STEP_01</Badge>
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-200">Infrastructure Setup</h3>
        </div>
        <p className="text-xs text-slate-500 font-sans leading-relaxed">Initialize an isolated Linux audit environment. Secure all ingress and egress traffic for monitoring tools.</p>
      </Card>
      
      <Card className="bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-2 mb-4">
          <Badge variant="info">STEP_02</Badge>
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-200">Recon Scan</h3>
        </div>
        <div className="bg-black/50 p-2 rounded border border-slate-800 font-mono text-[10px] text-blue-400">
           root@aegis:~# nmap -sV target.local
        </div>
      </Card>
    </div>
    
    <Card className="bg-black border border-slate-800 p-4 font-mono text-[11px] text-slate-500">
      <p className="mb-2 text-emerald-500 font-bold uppercase tracking-widest"># Standard_Checklist</p>
      <div className="space-y-1">
       <p>[ ] Perform DNS Zone Transfer Attempt</p>
       <p>[ ] Run Automated CVE Scanners</p>
       <p>[ ] Audit Header Strictness (HSTS/CSP)</p>
       <p>[ ] Final Report Generation & PGP Signing</p>
      </div>
    </Card>
  </div>
);

const EthicsSection = () => (
  <div className="space-y-6">
    <div className="bg-emerald-500/10 border border-emerald-500/30 p-8 rounded shadow-[0_0_50px_rgba(16,185,129,0.05)]">
      <div className="flex items-center gap-4 mb-6">
        <div className="w-14 h-14 bg-emerald-500/20 border border-emerald-500 rounded flex items-center justify-center shadow-[0_0_20px_rgba(16,185,129,0.3)]">
          <Shield className="w-8 h-8 text-emerald-400" />
        </div>
        <div>
          <h2 className="text-3xl font-bold text-emerald-400 tracking-tight uppercase">Ethical_Charter.v1</h2>
          <p className="text-xs text-slate-500 uppercase tracking-widest font-mono">Mission Statement and Professional Conduct</p>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="space-y-3">
          <h3 className="font-bold text-xs uppercase tracking-[0.2em] text-slate-200 border-b border-slate-800 pb-2">Authorization</h3>
          <p className="text-xs text-slate-500 leading-relaxed font-sans">Never audit systems without express written consent. Unauthorized access is illegal and violates professional standards.</p>
        </div>
        <div className="space-y-3">
          <h3 className="font-bold text-xs uppercase tracking-[0.2em] text-slate-200 border-b border-slate-800 pb-2">Transparency</h3>
          <p className="text-xs text-slate-500 leading-relaxed font-sans">Full disclosure to system owners. The audit's primary function is defense through structural improvement.</p>
        </div>
        <div className="space-y-3">
          <h3 className="font-bold text-xs uppercase tracking-[0.2em] text-slate-200 border-b border-slate-800 pb-2">Education</h3>
          <p className="text-xs text-slate-500 leading-relaxed font-sans">Empower defenders with knowledge. Security is a shared responsibility across the entire development stack.</p>
        </div>
      </div>
    </div>
  </div>
);

// --- Main App ---

export default function App() {
  const [activeTab, setActiveTab] = useState('recon');
  const [targetUrl, setTargetUrl] = useState('https://example.com');
  const [isScanning, setIsScanning] = useState(false);
  const [auditData, setAuditData] = useState<AuditResult | null>(null);

  const handleAudit = async () => {
    setIsScanning(true);
    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });
      const result = await response.json();
      setAuditData(result);
      setActiveTab('recon');
    } catch (error) {
      console.error('Audit failed:', error);
    } finally {
      setIsScanning(false);
    }
  };

  const sections = [
    { id: 'recon', title: 'RECON', icon: <Search className="w-4 h-4" />, content: <ReconSection data={auditData} /> },
    { id: 'vulns', title: 'VULNS', icon: <ShieldCheck className="w-4 h-4" />, content: <VulnerabilitySection data={auditData} /> },
    { id: 'admin', title: 'ADMIN', icon: <Lock className="w-4 h-4" />, content: <AdminSection data={auditData} /> },
    { id: 'guide', title: 'GUIDE', icon: <Terminal className="w-4 h-4" />, content: <AuditGuideSection /> },
    { id: 'remediation', title: 'PATCH', icon: <Terminal className="w-4 h-4" />, content: <RemediationSection /> },
    { id: 'ethics', title: 'ETHICS', icon: <BookOpen className="w-4 h-4" />, content: <EthicsSection /> },
  ];

  return (
    <div className="min-h-screen bg-[#020617] text-slate-300 font-sans p-4 md:p-8 border-8 border-slate-950 selection:bg-emerald-500/30 overflow-x-hidden">
      <div className="max-w-6xl mx-auto h-full flex flex-col">
        {/* Header Section */}
        <header className="flex flex-col md:flex-row items-center justify-between border-b border-emerald-500/30 pb-6 mb-8 gap-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-emerald-500/20 border border-emerald-500 rounded flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.3)]">
              <Shield className="w-7 h-7 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-emerald-400 uppercase">SENTINEL-X AUDIT ENGINE</h1>
              <p className="text-[10px] text-slate-500 uppercase tracking-[0.3em] font-mono font-bold">Security_Education_Framework_V3.0.4</p>
            </div>
          </div>
          
          <div className="flex flex-wrap gap-4 items-center justify-center md:justify-end flex-1 max-w-xl">
            <div className="relative flex-1 group">
              <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                <Globe className="w-4 h-4 text-emerald-500/50 group-focus-within:text-emerald-400 transition-colors" />
              </div>
              <input 
                type="text" 
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="TARGET_URL (e.g. example.com)"
                className="w-full bg-black/50 border border-slate-800 text-emerald-400 px-10 py-2.5 rounded font-mono text-xs focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/30 transition-all placeholder:text-slate-600"
              />
            </div>
            
            <button 
              onClick={handleAudit}
              disabled={isScanning}
              className="bg-emerald-600 text-white px-8 py-2.5 rounded font-bold hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all uppercase text-[10px] tracking-widest active:scale-95 flex items-center gap-2 group"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" />
                  ANALYZING_PHASES...
                </>
              ) : (
                <>
                  <Activity className="w-3 h-3 group-hover:animate-pulse" />
                  INIT_AUDIT
                </>
              )}
            </button>
          </div>
        </header>

        {/* Console Navigation */}
        <nav className="grid grid-cols-3 md:grid-cols-6 gap-2 mb-8">
          {sections.map((section) => (
            <button
              key={section.id}
              onClick={() => setActiveTab(section.id)}
              className={`flex flex-col items-center justify-center gap-2 p-4 border transition-all duration-200 rounded ${
                activeTab === section.id 
                  ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400 shadow-[inset_0_0_15px_rgba(16,185,129,0.1)]' 
                  : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700 hover:text-slate-300'
              }`}
            >
              <div className={activeTab === section.id ? 'text-emerald-400 scale-110 duration-200' : 'text-slate-600'}>
                {section.icon}
              </div>
              <span className="text-[10px] font-bold uppercase tracking-widest text-center mt-1">{section.title}</span>
            </button>
          ))}
        </nav>

        {/* Dashboard Metrics */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
           <div className="bg-black/40 border border-slate-800 p-4 rounded shadow-inner flex flex-col">
              <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest mb-1">Knowledge Units</span>
              <span className="text-2xl font-mono text-emerald-400">{auditData?.metrics.findings.toString().padStart(2, '0') || '00'}_</span>
           </div>
           <div className="bg-black/40 border border-slate-800 p-4 rounded shadow-inner flex flex-col">
              <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest mb-1">Critical Flaws</span>
              <span className="text-2xl font-mono text-red-500">{auditData?.vulnerabilities.filter(v => v.severity === 'CRITICAL').length.toString().padStart(2, '0') || '00'}_</span>
           </div>
           <div className="bg-black/40 border border-slate-800 p-4 rounded shadow-inner flex flex-col">
              <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest mb-1">Risk Index</span>
              <span className="text-2xl font-mono text-blue-400">{auditData?.risk_score || '0.0'}</span>
           </div>
           <div className="bg-black/40 border border-slate-800 p-4 rounded shadow-inner flex flex-col">
              <span className="text-[9px] text-slate-500 uppercase font-bold tracking-widest mb-1">Requests/Sec</span>
              <span className="text-2xl font-mono text-amber-500">{auditData?.metrics.reqSec || '0'}Hz</span>
           </div>
        </div>

        {/* Context Output */}
        <main className="flex-1 bg-slate-900/10 border border-slate-800/80 rounded p-6 mb-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, x: -5 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 5 }}
              transition={{ duration: 0.1, ease: "easeOut" }}
            >
              {sections.find(s => s.id === activeTab)?.content}
            </motion.div>
          </AnimatePresence>
        </main>

        {/* Footer Terminal Bar */}
        <footer className="mt-auto flex flex-col md:flex-row items-center justify-between text-[10px] text-slate-600 border-t border-slate-900 pt-6 font-mono uppercase tracking-widest gap-4">
          <div className="flex gap-8">
            <span>Uptime: <span className="text-blue-500">24:00:00</span></span>
            <span>Auth: <span className="text-emerald-500">VERIFIED_SECURE</span></span>
          </div>
          <div className="flex gap-8 items-center">
            <div className="flex items-center gap-2">
               <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
               <span>Operational_Status: STABLE</span>
            </div>
            <span>V3.0.4_Stable</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

