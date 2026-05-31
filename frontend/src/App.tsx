import React, { useState, useEffect, useRef } from "react";
import { 
  Play, 
  Shield, 
  Activity, 
  Terminal, 
  AlertTriangle, 
  FileCode, 
  Check, 
  Server, 
  Settings, 
  Code, 
  RefreshCw,
  Search,
  Globe,
  Database
} from "lucide-react";
import { mockVulnerabilityList, MockVulnerability } from "./mockData.ts";

export default function App() {
  // Configured dynamically from VITE_API_BASE_URL (falls back cleanly)
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

  // Form states
  const [targetUrl, setTargetUrl] = useState("https://example.com");
  const [cookie, setCookie] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);

  // Interface state controls
  const [activeTab, setActiveTab] = useState("scanner");
  const [selectedVuln, setSelectedVuln] = useState<MockVulnerability>(mockVulnerabilityList[0]);
  const [showPoc, setShowPoc] = useState(true);

  // Logging stdout buffer
  const [consoleLogs, setConsoleLogs] = useState<Array<{ time: string; type: "info" | "warning" | "error" | "success"; text: string }>>([
    { time: "20:30:01", type: "info", text: "AI Orchestrator initialized. Gemini 1.5 model loaded." },
    { time: "20:30:02", type: "success", text: "FastAPI REST API linked successfully to gateway." },
    { time: "20:30:02", type: "info", text: "Ready for un-authenticated or authenticated penetration requests." }
  ]);

  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll console window
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [consoleLogs]);

  // Simulated progress bar animation
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning && scanProgress < 100) {
      interval = setInterval(() => {
        setScanProgress((prev) => {
          const next = prev + Math.floor(Math.random() * 8) + 1;
          return next > 100 ? 100 : next;
        });
      }, 800);
    } else if (scanProgress === 100) {
      setIsScanning(false);
      addLog("info", "Vulnerability auditing completed. AI report compile sequence completed.");
    }
    return () => clearInterval(interval);
  }, [isScanning, scanProgress]);

  const addLog = (type: "info" | "warning" | "error" | "success", text: string) => {
    const now = new Date();
    const timeStr = now.toTimeString().split(" ")[0];
    setConsoleLogs((prev) => [...prev, { time: timeStr, type, text }]);
  };

  // Asynchronous API call to dispatch scan
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;

    setIsScanning(true);
    setScanProgress(0);
    setScanId(null);
    setConsoleLogs([]);

    addLog("info", `Initiating target handshake connection against: ${targetUrl}`);
    addLog("info", "Validating schema attributes via Pydantic model pipeline...");

    try {
      // Direct REST API Post request to FastAPI Backend (No hardcoding)
      const response = await fetch(`${API_BASE_URL}/api/v1/scan/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target_url: targetUrl,
          cookie: cookie || null
        })
      });

      if (!response.ok) {
        const errDetails = await response.json();
        throw new Error(errDetails.detail || "API dispatcher error code received.");
      }

      const data = await response.json();
      setScanId(data.scan_id);
      
      addLog("success", `FastAPI Server Accepted Request. Generated ID: ${data.scan_id}`);
      addLog("info", `Spawning isolated Nuclei subprocess securely in background. Shell validation: OK.`);
      addLog("info", `Command list constructed: ["-target", "${targetUrl}", "-severity", "critical,high", "-jsonl"]`);
      
      if (cookie) {
        addLog("info", `Dynamic Authentication headers injected into subprocess arguments.`);
      }

      // Add a delayed mock warning line to simulate active stream processing
      setTimeout(() => {
        addLog("warning", "CRITICAL THREAT IDENTIFIED: ThinkPHP 5.x RCE module triggered callback.");
      }, 3000);

      setTimeout(() => {
        addLog("info", "Processing template results. Handing vulnerability context payload to Gemini AI...");
      }, 7000);

    } catch (error: any) {
      addLog("error", `Engine Dispatch Exception: ${error.message}`);
      addLog("error", "Verify that your FastAPI backend is running and that CORS matches VITE_API_BASE_URL.");
      setIsScanning(false);
    }
  };

  return (
    <div className="flex h-screen bg-cyber-bg text-slate-100 overflow-hidden font-sans">
      
      {/* 1. LEFT SIDEBAR - CYBERPUNK NAV DESIGN */}
      <aside className="w-64 bg-cyber-darker border-r border-cyber-border flex flex-col justify-between shrink-0">
        <div>
          {/* Dashboard Branding Header */}
          <div className="p-6 border-b border-cyber-border flex items-center gap-3">
            <div className="relative">
              <div className="w-8 h-8 rounded bg-gradient-to-br from-cyber-primary to-cyber-secondary flex items-center justify-center text-white font-extrabold shadow-[0_0_15px_rgba(99,102,241,0.5)]">
                AI
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-cyber-secondary rounded-full border border-cyber-bg animate-pulse"></span>
            </div>
            <div>
              <h1 className="font-extrabold text-sm tracking-wider uppercase bg-clip-text text-transparent bg-gradient-to-r from-indigo-200 to-white">
                AI-PT Platform
              </h1>
              <p className="text-[10px] text-cyber-secondary font-mono tracking-widest uppercase animate-pulse-slow">
                Active Audit Suite
              </p>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="p-4 space-y-1">
            <button
              onClick={() => setActiveTab("scanner")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-all duration-300 ${
                activeTab === "scanner"
                  ? "bg-slate-900 border border-cyber-border text-white shadow-[0_0_10px_rgba(99,102,241,0.15)]"
                  : "text-slate-400 hover:text-white hover:bg-slate-950"
              }`}
            >
              <Terminal className={`w-4 h-4 ${activeTab === "scanner" ? "text-cyber-primary" : ""}`} />
              <span className="font-medium">Vulnerability Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab("vulnerabilities")}
              className={`w-full flex items-center justify-between px-4 py-3 rounded-lg text-sm transition-all duration-300 ${
                activeTab === "vulnerabilities"
                  ? "bg-slate-900 border border-cyber-border text-white shadow-[0_0_10px_rgba(99,102,241,0.15)]"
                  : "text-slate-400 hover:text-white hover:bg-slate-950"
              }`}
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className={`w-4 h-4 ${activeTab === "vulnerabilities" ? "text-cyber-accent" : ""}`} />
                <span className="font-medium">AI Audit Reports</span>
              </div>
              <span className="text-[10px] bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent px-1.5 py-0.5 rounded font-mono font-bold animate-pulse">
                {mockVulnerabilityList.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab("configs")}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-all duration-300 ${
                activeTab === "configs"
                  ? "bg-slate-900 border border-cyber-border text-white"
                  : "text-slate-400 hover:text-white hover:bg-slate-950"
              }`}
            >
              <Settings className="w-4 h-4" />
              <span className="font-medium">System Configurations</span>
            </button>
          </nav>
        </div>

        {/* Global Connection Health Status (Dynamic UI) */}
        <div className="p-4 border-t border-cyber-border bg-slate-950/60">
          <div className="flex items-center gap-3 text-xs">
            <div className="w-2.5 h-2.5 rounded-full bg-cyber-secondary animate-ping"></div>
            <div>
              <div className="flex items-center gap-1.5 font-bold">
                <Server className="w-3.5 h-3.5 text-cyber-secondary" />
                <span>Backend Gateway</span>
              </div>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5 truncate select-none">
                {API_BASE_URL}
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* 2. MAIN CONTAINER */}
      <main className="flex-1 flex flex-col overflow-hidden bg-gradient-to-b from-slate-950 via-cyber-bg to-slate-950">
        
        {/* TOP STATUS HEADER PANEL */}
        <header className="h-16 border-b border-cyber-border px-8 flex items-center justify-between shrink-0 glass-card">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyber-secondary" />
              <span className="text-xs text-slate-400">Core Engine:</span>
              <span className="text-xs font-mono font-bold text-cyber-secondary bg-cyber-secondary/10 px-2 py-0.5 rounded border border-cyber-secondary/20">
                ACTIVE
              </span>
            </div>
            <div className="w-px h-4 bg-cyber-border hidden sm:block"></div>
            <div className="hidden sm:flex items-center gap-2">
              <Database className="w-4 h-4 text-cyber-primary" />
              <span className="text-xs text-slate-400">LLM Decider:</span>
              <span className="text-xs font-mono font-bold text-cyber-primary bg-cyber-primary/10 px-2 py-0.5 rounded border border-cyber-primary/20">
                GEMINI-1.5-FLASH
              </span>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400 font-mono">{new Date().toLocaleDateString("en-CA")} {Intl.DateTimeFormat().resolvedOptions().timeZone}</span>
          </div>
        </header>

        {/* WORKSPACE AREA */}
        <div className="flex-1 overflow-y-auto p-8">
          
          {/* TAB 1: INTEGRATED ACTIVE VULNERABILITY SCANNER */}
          {activeTab === "scanner" && (
            <div className="space-y-8">
              
              {/* Form and Faux Terminal Grid Layout */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Control Console Form */}
                <div className="lg:col-span-5 space-y-6">
                  <div className="bg-slate-900/90 border border-cyber-border rounded-xl p-6 shadow-xl relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none"></div>
                    
                    <div className="flex items-center gap-2 mb-6">
                      <Shield className="w-5 h-5 text-cyber-primary" />
                      <h2 className="font-extrabold text-base tracking-wide">
                        Scanner Controller
                      </h2>
                    </div>

                    <form onSubmit={handleLaunchScan} className="space-y-5">
                      {/* Target Address Input */}
                      <div className="space-y-2">
                        <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest">
                          Target URL Address
                        </label>
                        <div className="relative">
                          <Globe className="absolute left-3.5 top-3.5 w-4 h-4 text-slate-500" />
                          <input
                            type="text"
                            required
                            placeholder="https://example.com"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            disabled={isScanning}
                            className="w-full bg-slate-950 border border-cyber-border rounded-lg pl-10 pr-4 py-3 text-sm font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary transition-all duration-300"
                          />
                        </div>
                        <p className="text-[10px] text-slate-500">
                          Starts with standard http:// or https://. Will be parsed via FastAPI validation schema.
                        </p>
                      </div>

                      {/* Header Cookies Input */}
                      <div className="space-y-2">
                        <label className="block text-xs font-bold text-slate-400 uppercase tracking-widest">
                          Audit Session Cookie (Optional)
                        </label>
                        <textarea
                          placeholder="PHPSESSID=abcdef123456; security=low"
                          value={cookie}
                          onChange={(e) => setCookie(e.target.value)}
                          disabled={isScanning}
                          rows={3}
                          className="w-full bg-slate-950 border border-cyber-border rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary transition-all duration-300"
                        />
                        <p className="text-[10px] text-slate-500">
                          Injected directly into Nuclei subprocess argument header configurations safely.
                        </p>
                      </div>

                      {/* Launch Trigger Button */}
                      <button
                        type="submit"
                        disabled={isScanning}
                        className={`w-full py-3.5 rounded-lg text-sm font-extrabold tracking-wider uppercase transition-all duration-300 flex items-center justify-center gap-3 ${
                          isScanning
                            ? "bg-slate-950 border border-cyber-border text-slate-500 cursor-not-allowed"
                            : "bg-gradient-to-r from-cyber-primary to-indigo-700 text-white hover:shadow-[0_0_20px_rgba(99,102,241,0.4)] cursor-pointer"
                        }`}
                      >
                        {isScanning ? (
                          <>
                            <RefreshCw className="w-4 h-4 animate-spin text-cyber-primary" />
                            <span>Scan Audit In Progress...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-4 h-4 text-white fill-white" />
                            <span>Launch AI Penetration Scan</span>
                          </>
                        )}
                      </button>
                    </form>
                  </div>
                </div>

                {/* Simulated Console Logger Container */}
                <div className="lg:col-span-7 space-y-6">
                  <div className="bg-slate-950 border border-cyber-border rounded-xl flex flex-col h-[400px] overflow-hidden shadow-2xl relative">
                    
                    {/* Console Tab header controls */}
                    <div className="bg-cyber-darker border-b border-cyber-border px-4 py-3 flex items-center justify-between shrink-0">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                        <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                        <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                        <span className="text-xs font-mono font-bold text-slate-400 ml-3">
                          stdout-terminal@engine
                        </span>
                      </div>
                      {scanId && (
                        <span className="text-[10px] font-mono text-slate-500 truncate max-w-[200px]">
                          UUID: {scanId}
                        </span>
                      )}
                    </div>

                    {/* Faux logging streams */}
                    <div className="flex-1 overflow-y-auto p-5 font-mono text-xs space-y-3.5 bg-slate-950/80 terminal-scroll">
                      {consoleLogs.map((log, idx) => (
                        <div key={idx} className="flex items-start gap-3">
                          <span className="text-slate-600 shrink-0 select-none">[{log.time}]</span>
                          <span className={`shrink-0 select-none uppercase font-bold text-[10px] px-1.5 py-0.5 rounded ${
                            log.type === "info" ? "bg-blue-500/10 text-blue-400 border border-blue-500/20" :
                            log.type === "success" ? "bg-cyber-secondary/10 text-cyber-secondary border border-cyber-secondary/20" :
                            log.type === "warning" ? "bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20 animate-pulse" :
                            "bg-red-500/10 text-red-400 border border-red-500/20"
                          }`}>
                            {log.type}
                          </span>
                          <span className={`leading-relaxed ${
                            log.type === "warning" ? "text-cyber-accent font-bold" :
                            log.type === "error" ? "text-red-400" :
                            log.type === "success" ? "text-emerald-300" :
                            "text-slate-300"
                          }`}>
                            {log.text}
                          </span>
                        </div>
                      ))}
                      <div ref={consoleEndRef} />
                    </div>

                    {/* Progress tracking indicator */}
                    <div className="bg-cyber-darker border-t border-cyber-border p-4 flex items-center gap-4 shrink-0">
                      <div className="flex-1 bg-slate-900 h-2 rounded-full overflow-hidden border border-cyber-border">
                        <div 
                          className="bg-gradient-to-r from-cyber-primary to-cyber-secondary h-full rounded-full transition-all duration-500 ease-out shadow-[0_0_10px_rgba(99,102,241,0.5)]"
                          style={{ width: `${scanProgress}%` }}
                        ></div>
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-300 shrink-0 w-10 text-right">
                        {scanProgress}%
                      </span>
                    </div>

                  </div>
                </div>

              </div>

              {/* Quick Navigation to Vulnerabilities section on finding */}
              <div className="border border-cyber-border bg-slate-900/40 rounded-xl p-6 flex flex-col md:flex-row items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-cyber-accent" />
                  <div>
                    <h3 className="font-bold text-sm">Target Scanning Findings Detected</h3>
                    <p className="text-xs text-slate-400">
                      Auditor found vulnerabilities matching critical threat templates. Dynamic AI patching recommendations generated.
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setActiveTab("vulnerabilities")}
                  className="px-5 py-2.5 bg-slate-950 border border-cyber-border text-white text-xs font-bold rounded-lg hover:border-cyber-primary transition-all duration-300 shrink-0"
                >
                  View AI Remediation Logs
                </button>
              </div>

            </div>
          )}

          {/* TAB 2: AI VULNERABILITY AUDIT REPORTS & REMEDIATION COMPARISONS */}
          {activeTab === "vulnerabilities" && (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
              
              {/* Left Column: Vulnerability list selection */}
              <div className="xl:col-span-4 space-y-4">
                <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4 flex items-center gap-2">
                  <Search className="w-3.5 h-3.5 text-slate-400" />
                  Vulnerability Findings List
                </h2>
                <div className="space-y-3">
                  {mockVulnerabilityList.map((vuln) => (
                    <button
                      key={vuln.id}
                      onClick={() => {
                        setSelectedVuln(vuln);
                      }}
                      className={`w-full text-left p-4 rounded-xl border transition-all duration-300 flex flex-col gap-2.5 ${
                        selectedVuln.id === vuln.id
                          ? "bg-slate-900 border-cyber-accent/60 shadow-[0_0_15px_rgba(244,63,94,0.1)]"
                          : "bg-cyber-darker/60 border-cyber-border hover:bg-cyber-darker"
                      }`}
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-[10px] font-mono text-slate-500 font-bold">
                          {vuln.id}
                        </span>
                        <span className={`text-[9px] font-mono font-extrabold px-2 py-0.5 rounded border ${
                          vuln.severity === "CRITICAL"
                            ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                            : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                        }`}>
                          {vuln.severity}
                        </span>
                      </div>
                      <h3 className="font-extrabold text-sm text-slate-200 truncate">
                        {vuln.name}
                      </h3>
                      <p className="text-[11px] text-slate-500 font-mono truncate">
                        {vuln.path}
                      </p>
                    </button>
                  ))}
                </div>
              </div>

              {/* Right Column: Detailed analysis and AI patch comparison */}
              <div className="xl:col-span-8 space-y-6">
                
                {/* Vulnerability Metadata */}
                <div className="bg-slate-900/90 border border-cyber-border rounded-xl p-6 shadow-xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-40 h-40 bg-rose-500/5 rounded-full blur-3xl pointer-events-none"></div>
                  
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-xs text-cyber-accent font-mono font-bold">
                      {selectedVuln.id}
                    </span>
                    <span className={`text-[10px] font-mono font-extrabold px-3 py-1 rounded-full border ${
                      selectedVuln.severity === "CRITICAL"
                        ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                        : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    }`}>
                      {selectedVuln.severity} Severity Threat
                    </span>
                  </div>

                  <h2 className="font-extrabold text-lg text-slate-100 mb-3">
                    {selectedVuln.name}
                  </h2>
                  
                  <p className="text-xs text-slate-400 leading-relaxed bg-slate-950/50 p-4 rounded-lg border border-cyber-border mb-6">
                    {selectedVuln.description}
                  </p>

                  {/* PoC and Code Tabs */}
                  <div className="flex border-b border-cyber-border mb-5">
                    <button
                      onClick={() => setShowPoc(true)}
                      className={`px-4 py-2 text-xs font-bold transition-all duration-300 border-b-2 ${
                        showPoc
                          ? "border-cyber-accent text-white"
                          : "border-transparent text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      PoC Attack Vector Details
                    </button>
                    <button
                      onClick={() => setShowPoc(false)}
                      className={`px-4 py-2 text-xs font-bold transition-all duration-300 border-b-2 ${
                        !showPoc
                          ? "border-cyber-primary text-white"
                          : "border-transparent text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      AI Code Patch Remediation
                    </button>
                  </div>

                  {/* PoC Details Tab View */}
                  {showPoc && (
                    <div className="space-y-4">
                      <div className="space-y-2">
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-cyber-accent" />
                          Simulated Exploit Payload (PoC HTTP Request)
                        </span>
                        <pre className="bg-slate-950/90 border border-cyber-border p-4 rounded-lg text-xs font-mono text-red-300 overflow-x-auto leading-relaxed shadow-inner">
                          {selectedVuln.pocRequest}
                        </pre>
                      </div>
                      <div className="space-y-2">
                        <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest flex items-center gap-1.5">
                          <Check className="w-3.5 h-3.5 text-cyber-secondary" />
                          Subprocess Callback Validation (PoC HTTP Response)
                        </span>
                        <pre className="bg-slate-950/90 border border-cyber-border p-4 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto leading-relaxed shadow-inner">
                          {selectedVuln.pocResponse}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* AI Remediation Diff Tab View */}
                  {!showPoc && (
                    <div className="space-y-6">
                      
                      {/* Remediate explanation banner */}
                      <div className="bg-cyber-primary/10 border border-cyber-primary/30 p-4 rounded-lg flex items-start gap-3">
                        <FileCode className="w-5 h-5 text-cyber-primary shrink-0 mt-0.5" />
                        <div>
                          <h4 className="text-xs font-bold text-slate-200">Gemini AI Patch Advisory</h4>
                          <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                            Vulnerability mitigated by introducing controller namespaces checking. The patch restricts class instantiations to verified child classes inheriting standard controllers, closing the dynamic parameters execution pipeline.
                          </p>
                        </div>
                      </div>

                      {/* Code comparison container */}
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono text-[11px]">
                        
                        {/* Vulnerable block */}
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-[10px] font-bold text-rose-400 uppercase tracking-widest">
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                              Vulnerable Code (Source)
                            </span>
                          </div>
                          <pre className="bg-rose-950/20 border border-rose-950/40 p-4 rounded-lg text-rose-300/90 overflow-x-auto h-[320px] shadow-inner select-all leading-normal">
                            {selectedVuln.vulnCode}
                          </pre>
                        </div>

                        {/* Remediated block */}
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-[10px] font-bold text-emerald-400 uppercase tracking-widest">
                            <span className="flex items-center gap-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                              AI Remediation Code (Secure)
                            </span>
                          </div>
                          <pre className="bg-emerald-950/20 border border-emerald-950/40 p-4 rounded-lg text-emerald-300/90 overflow-x-auto h-[320px] shadow-inner select-all leading-normal">
                            {selectedVuln.patchedCode}
                          </pre>
                        </div>

                      </div>
                    </div>
                  )}

                </div>

              </div>

            </div>
          )}

          {/* TAB 3: SYSTEM CONTEXT CONFIGURATION VIEW */}
          {activeTab === "configs" && (
            <div className="max-w-2xl space-y-6">
              <div className="bg-slate-900 border border-cyber-border rounded-xl p-6 shadow-xl relative">
                
                <div className="flex items-center gap-2 mb-6">
                  <Settings className="w-5 h-5 text-cyber-primary" />
                  <h2 className="font-extrabold text-base tracking-wide">
                    FastAPI Configuration Dashboard
                  </h2>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-slate-950 border border-cyber-border rounded-lg flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-300">FastAPI API Service Port</h4>
                      <p className="text-[10px] text-slate-500 mt-0.5">API_PORT read dynamically on server runtime config.</p>
                    </div>
                    <span className="font-mono text-sm bg-slate-900 border border-cyber-border px-3 py-1 rounded font-bold text-cyber-primary">
                      8000
                    </span>
                  </div>

                  <div className="p-4 bg-slate-950 border border-cyber-border rounded-lg flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-300">Local Nuclei Binary Path</h4>
                      <p className="text-[10px] text-slate-500 mt-0.5">Absolute system execution binary path validation.</p>
                    </div>
                    <span className="font-mono text-[10px] bg-slate-900 border border-cyber-border px-3 py-1 rounded font-bold text-emerald-400 max-w-xs truncate">
                      C:\tools\nuclei.exe
                    </span>
                  </div>

                  <div className="p-4 bg-slate-950 border border-cyber-border rounded-lg flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-bold text-slate-300">FastAPI Logger Output Level</h4>
                      <p className="text-[10px] text-slate-500 mt-0.5">LOG_LEVEL settings for diagnostics reporting.</p>
                    </div>
                    <span className="font-mono text-xs bg-slate-900 border border-cyber-border px-3 py-1 rounded font-bold text-indigo-400">
                      INFO
                    </span>
                  </div>
                </div>

              </div>
            </div>
          )}

        </div>

      </main>

    </div>
  );
}
