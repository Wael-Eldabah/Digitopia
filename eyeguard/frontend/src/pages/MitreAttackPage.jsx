// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';

const tactics = [
  {
    name: 'Reconnaissance',
    objective: 'Understand the target environment and enumerate exposed assets prior to intrusion.',
    techniques: ['Active Scanning (T1595)', 'Gather Victim Identity Information (T1589)', 'Phishing for Information (T1598)'],
  },
  {
    name: 'Resource Development',
    objective: 'Establish infrastructure, malware, and accounts used later in the intrusion lifecycle.',
    techniques: ['Acquire Infrastructure (T1583)', 'Establish Accounts (T1585)', 'Develop Malware (T1587)'],
  },
  {
    name: 'Initial Access',
    objective: 'Obtain a foothold into the environment through exposed services, users, or supply chain.',
    techniques: ['Spearphishing Attachment (T1566.001)', 'Exploit Public-Facing Application (T1190)', 'Drive-by Compromise (T1189)'],
  },
  {
    name: 'Execution',
    objective: 'Run attacker-controlled code on local or remote systems to begin post-exploitation.',
    techniques: ['Command and Scripting Interpreter (T1059)', 'PowerShell (T1059.001)', 'Scheduled Task/Job (T1053)'],
  },
  {
    name: 'Persistence',
    objective: 'Maintain access to compromised systems even when credentials or hosts are reset.',
    techniques: ['Account Manipulation (T1098)', 'Boot or Logon Autostart Execution (T1547)', 'Modify Registry (T1112)'],
  },
  {
    name: 'Privilege Escalation',
    objective: 'Gain higher-level permissions to widen the blast radius inside the environment.',
    techniques: ['Exploitation for Privilege Escalation (T1068)', 'Valid Accounts (T1078)', 'Access Token Manipulation (T1134)'],
  },
  {
    name: 'Defense Evasion',
    objective: 'Disable, modify, or evade security tooling to avoid detection and response.',
    techniques: ['Obfuscated/Compressed Files (T1027)', 'Credential Dumping (T1003)', 'Masquerading (T1036)'],
  },
  {
    name: 'Credential Access',
    objective: 'Harvest credentials from memory, files, or network traffic to propagate laterally.',
    techniques: ['OS Credential Dumping (T1003.001)', 'Input Capture (T1056)', 'Brute Force (T1110)'],
  },
  {
    name: 'Discovery',
    objective: 'Inventory hosts, services, and security controls to inform next steps.',
    techniques: ['Network Service Scanning (T1046)', 'Account Discovery (T1087)', 'System Information Discovery (T1082)'],
  },
  {
    name: 'Lateral Movement',
    objective: 'Pivot into additional hosts and services to deepen control across the environment.',
    techniques: ['Remote Services (T1021)', 'Windows Remote Management (T1028)', 'Pass the Hash (T1075)'],
  },
  {
    name: 'Collection',
    objective: 'Stage data of interest for exfiltration or impact operations.',
    techniques: ['Archive Collected Data (T1560)', 'Screen Capture (T1113)', 'Input Capture (T1056)'],
  },
  {
    name: 'Command and Control',
    objective: 'Maintain communications channels between compromised hosts and operator infrastructure.',
    techniques: ['Web Protocols (T1071)', 'Domain Fronting (T1090.004)', 'Fallback Channels (T1008)'],
  },
  {
    name: 'Exfiltration',
    objective: 'Exfiltrate collected data or secrets from the environment without detection.',
    techniques: ['Exfiltration Over Web Services (T1567)', 'Exfiltration Over Alternative Protocol (T1048)', 'Scheduled Transfer (T1029)'],
  },
  {
    name: 'Impact',
    objective: 'Disrupt availability, destroy data, or manipulate integrity to achieve objectives.',
    techniques: ['Data Destruction (T1485)', 'Data Encrypted for Impact (T1486)', 'Service Stop (T1489)'],
  },
];

const detectionFocuses = [
  {
    title: 'Network Layer',
    description: 'Correlate PCAP analysis with MITRE techniques such as C2 over HTTP/S, beacon intervals, and lateral movement protocols.',
  },
  {
    title: 'Endpoint Telemetry',
    description: 'Leverage simulated EDR events for persistence and privilege escalation detections mapped to ATT&CK tactics.',
  },
  {
    title: 'Identity Signals',
    description: 'Monitor authentication anomalies, delegated access, and token manipulation against credential access techniques.',
  },
  {
    title: 'Cloud & SaaS',
    description: 'Map cloud audit events, API calls, and IAM misconfigurations to relevant MITRE tactics for SaaS attack paths.',
  },
];

const responsePlaybooks = [
  {
    name: 'Containment & Eradication',
    steps: [
      'Isolate compromised assets and disable malicious persistence mechanisms.',
      'Rotate credentials and tokens associated with validated ATT&CK techniques.',
      'Deploy host-based remediation scripts targeted at identified execution vectors.',
    ],
  },
  {
    name: 'Investigation Workflow',
    steps: [
      'Pivot across EyeGuard alerts with shared ATT&CK tags to identify intrusion scope.',
      'Correlate timeline of tactics observed with available PCAP and simulation telemetry.',
      'Document observed techniques for post-incident knowledge base enrichment.',
    ],
  },
  {
    name: 'Readiness & Purple Teaming',
    steps: [
      'Select ATT&CK techniques and run EyeGuard simulations to validate detection efficacy.',
      'Track detection coverage gaps and prioritize engineering workstreams.',
      'Share findings with defenders using ATT&CK-aligned reporting templates.',
    ],
  },
];

export default function MitreAttackPage() {
  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">MITRE ATT&CK Framework</h1>
        <p className="text-sm text-slate-400">
          Navigate adversary tradecraft with ATT&CK-mapped tactics, techniques, detections, and response workflows inside EyeGuard.
        </p>
      </header>

      <section className="grid gap-4 rounded-3xl border border-sky-500/30 bg-sky-500/10 p-6 sm:grid-cols-3">
        <div className="sm:col-span-2 space-y-2">
          <p className="text-xs uppercase tracking-wide text-sky-200/80">Why ATT&CK</p>
          <h2 className="text-xl font-semibold text-slate-100">Threat-informed defense baseline</h2>
          <p className="text-sm text-slate-200/90 leading-relaxed">
            Align EyeGuard detections, simulation scenarios, and reports to the MITRE ATT&CK knowledge base.
            Use the matrix below to brief stakeholders, prioritize gap closure, and accelerate purple team iterations.
          </p>
        </div>
        <div className="rounded-2xl border border-sky-500/30 bg-slate-950/60 p-4 text-sm text-slate-300">
          <p className="text-xs text-slate-500 uppercase">Quick reference</p>
          <ul className="mt-2 space-y-1">
            <li>14 tactics</li>
            <li>188+ enterprise techniques (subset sampled below)</li>
            <li>Lifecycle-aligned investigative guidance</li>
          </ul>
        </div>
      </section>

      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Enterprise tactics overview</h2>
          <p className="text-sm text-slate-400">Key objectives and representative techniques observed by threat actors.</p>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {tactics.map((tactic) => (
            <article key={tactic.name} className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-[0_18px_45px_rgba(8,18,35,0.45)]">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-wide text-slate-500">{tactic.name}</p>
                  <h3 className="text-lg font-semibold text-slate-100">{tactic.objective}</h3>
                </div>
                <span className="rounded-full border border-slate-700 px-3 py-1 text-[11px] font-semibold text-slate-300">
                  Tactic
                </span>
              </div>
              <ul className="mt-4 space-y-2 text-sm text-slate-300">
                {tactic.techniques.map((technique) => (
                  <li key={technique} className="flex items-start gap-2">
                    <span className="mt-[6px] h-1.5 w-1.5 flex-none rounded-full bg-sky-400/80" />
                    <span>{technique}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-100">Detection coverage pivots</h2>
            <p className="text-sm text-slate-400">Layer EyeGuard telemetry sources to track ATT&CK-informed detections.</p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-4 py-1 text-xs text-emerald-200">
            <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            Detection Engineering
          </span>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          {detectionFocuses.map((item) => (
            <div key={item.title} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <h3 className="text-base font-semibold text-slate-100">{item.title}</h3>
              <p className="mt-2 text-sm text-slate-300 leading-relaxed">{item.description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Operational playbooks</h2>
          <p className="text-sm text-slate-400">Structure incident response actions around techniques exploited by adversaries.</p>
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          {responsePlaybooks.map((playbook) => (
            <div key={playbook.name} className="rounded-2xl border border-slate-800 bg-[#101b33] p-5">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-base font-semibold text-slate-100">{playbook.name}</h3>
                <span className="text-[11px] uppercase tracking-wide text-slate-500">Playbook</span>
              </div>
              <ol className="mt-3 space-y-2 text-sm text-slate-300">
                {playbook.steps.map((step) => (
                  <li key={step} className="flex gap-2">
                    <span className="text-slate-500">•</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
