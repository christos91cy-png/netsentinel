import { create } from 'zustand';
import { ScanSummary } from '../types';
import { invoke } from '@tauri-apps/api/core';

interface HistoryStore {
  summaries: ScanSummary[];
  loaded: boolean;
  load: () => Promise<void>;
  remove: (id: number) => void;
  prepend: (s: ScanSummary) => void;
}

export const useHistoryStore = create<HistoryStore>((set, get) => ({
  summaries: [],
  loaded: false,
  load: async () => {
    if (get().loaded) return;
    const data = await invoke<ScanSummary[]>('get_scan_history');
    set({ summaries: data, loaded: true });
  },
  remove: (id) => set((s) => ({ summaries: s.summaries.filter((x) => x.id !== id) })),
  prepend: (summary) => set((s) => ({ summaries: [summary, ...s.summaries] })),
}));
