export interface Port {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
}

export interface Vuln {
  port: number;
  script_id: string;
  output: string;
}

export interface ScanResult {
  target: string;
  scan_type: string;
  started_at: string;
  ports: Port[];
  vulns: Vuln[];
  os_guess?: string;
}

export interface ScanSummary {
  id: number;
  target: string;
  scan_type: string;
  started_at: string;
  port_count: number;
  vuln_count: number;
}

export interface ShodanHost {
  ip: string;
  ports: number[];
  hostnames: string[];
  tags: string[];
  cpes: string[];
  vulns: string[];
}
