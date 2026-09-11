/**
 * JOCKY Forensic DSL Compiler IDE Script
 * Handles real-time compilation, AST visualization, LLVM IR inspection, and live execution telemetry.
 */

const JOCKY_EXAMPLES = {
  'basic_scan': `// JOCKY Basic Forensic Triage Workflow
// Evaluates active system processes, sockets, and basic IOC matches

TARGET SYSTEM;

SCAN PROCESSES;
SCAN NETWORK;

FIND IOC;

BUILD TIMELINE;

EXPORT REPORT;
`,

  'full_investigation': `// JOCKY Comprehensive Multi-Source Forensic Sweep
// Aggregates process snapshots, filesystem artifacts, registry keys, and event logs

TARGET SYSTEM;

SET output_format = "JSON";
SET severity_threshold = "HIGH";

SCAN PROCESSES;
SCAN FILES;
SCAN NETWORK;
SCAN EVENTLOGS;
SCAN REGISTRY;

FIND IOC;
FIND SUSPICIOUS;
FIND PERSISTENCE;

BUILD TIMELINE;
BUILD CORRELATIONS;
BUILD PROCESSGRAPH;

EXPORT REPORT TO "full_investigation_report";
`,

  'network_analysis': `// JOCKY Network Threat Correlation Script
// Maps open network sockets directly to PIDs and parent executables

TARGET SYSTEM;

SCAN NETWORK;
SCAN PROCESSES;

FIND IOC;

BUILD CORRELATIONS;
BUILD TIMELINE;

EXPORT REPORT TO "network_telemetry_report";
`,

  'ioc_hunt': `// JOCKY Targeted IOC & LOLBins Signature Hunting
// Cross-references active processes & run keys against known threat patterns

TARGET SYSTEM;

SCAN PROCESSES;
SCAN NETWORK;
SCAN REGISTRY;

FIND IOC;
FIND MALWARE;
FIND SUSPICIOUS;
FIND PERSISTENCE;

BUILD TIMELINE;
BUILD CORRELATIONS;

EXPORT REPORT TO "ioc_hunt_results";
`
};

window.editorApp = {
  code: JOCKY_EXAMPLES['basic_scan'],
  isCompiling: false,
  isExecuting: false,
  activeOutputTab: 'ast', // 'ast', 'ir', 'results'
  astOutput: null,
  irOutput: null,
  execResults: null,
  execStats: null,
  investigationId: null,
  
  loadExample(name) {
    if (JOCKY_EXAMPLES[name]) {
      this.code = JOCKY_EXAMPLES[name];
      window.dispatchEvent(new CustomEvent('toast', { 
        detail: { message: `Loaded [${name.toUpperCase()}] forensic playbook`, type: 'info' }
      }));
    }
  },

  async compileScript() {
    if (!this.code || !this.code.trim()) {
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: 'DSL script buffer is empty', type: 'error' } }));
        return;
    }
    
    this.isCompiling = true;
    try {
      const endpoint = this.investigationId 
        ? `/investigations/${this.investigationId}/compile` 
        : `/compiler/compile`;
        
      const res = await window.apiClient.post(endpoint, { source: this.code });
      
      if (res) {
        this.astOutput = typeof res.ast === 'object' ? JSON.stringify(res.ast, null, 2) : res.ast;
        this.irOutput = res.llvm_ir || "; LLVM IR generated\n";
        this.activeOutputTab = 'ir';
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: 'Compilation & LLVM IR generated successfully!', type: 'success' } }));
      }
    } catch (err) {
      this.astOutput = `[X] Compilation Error: ${err.message}`;
      this.irOutput = `; Compilation aborted due to error: ${err.message}`;
      this.activeOutputTab = 'ast';
      window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Compilation Error: ${err.message}`, type: 'error' } }));
    } finally {
      this.isCompiling = false;
    }
  },

  async executeScript() {
    if (!this.code || !this.code.trim()) return;
    
    this.isExecuting = true;
    this.activeOutputTab = 'results';
    this.execResults = [
        { type: 'info', message: '[*] Initializing JOCKY isolated forensic runtime...', timestamp: new Date().toISOString() },
        { type: 'info', message: '[*] Compiling AST & dispatching to OS forensic adapter...', timestamp: new Date().toISOString() }
    ];
    
    try {
      const endpoint = this.investigationId 
        ? `/investigations/${this.investigationId}/execute` 
        : `/compiler/execute`;
        
      const res = await window.apiClient.post(endpoint, { source: this.code });
      
      if (res) {
        if (res.logs && res.logs.length > 0) {
            this.execResults = res.logs;
        } else {
            this.execResults.push({ type: 'success', message: `Execution completed in ${res.execution_time || 0.4}s`, timestamp: new Date().toISOString() });
        }
        this.execStats = res.results || null;
        window.dispatchEvent(new CustomEvent('toast', { detail: { message: 'Forensic execution completed successfully!', type: 'success' } }));
      }
    } catch (err) {
      this.execResults.push({ type: 'error', message: `[!] Runtime exception: ${err.message}`, timestamp: new Date().toISOString() });
      window.dispatchEvent(new CustomEvent('toast', { detail: { message: `Execution failed: ${err.message}`, type: 'error' } }));
    } finally {
      this.isExecuting = false;
    }
  },
  
  handleKeydown(e) {
    if (e.ctrlKey && e.key === 'Enter') {
      e.preventDefault();
      this.executeScript();
    }
  }
};
