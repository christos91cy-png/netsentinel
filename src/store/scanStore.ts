import { create } from 'zustand';
import { ScanResult } from '../types';

interface ScanProgress {
  percent: number;
  phase: string;
  elapsed_secs: number;
}

interface ScanStore {
  isScanning: boolean;
  progress: ScanProgress | null;
  currentResult: ScanResult | null;
  error: string | null;
  setScanning: (v: boolean) => void;
  setProgress: (p: ScanProgress) => void;
  setResult: (r: ScanResult | null) => void;
  setError: (e: string | null) => void;
  reset: () => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  isScanning: false,
  progress: null,
  currentResult: null,
  error: null,
  setScanning: (v) => set({ isScanning: v }),
  setProgress: (p) => set({ progress: p }),
  setResult: (r) => set({ currentResult: r }),
  setError: (e) => set({ error: e }),
  reset: () => set({ isScanning: false, progress: null, error: null }),
}));
