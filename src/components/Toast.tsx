import { createContext, useContext, useReducer, useCallback, ReactNode } from 'react';
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react';

interface Toast {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
}

interface ToastCtx {
  toasts: Toast[];
  addToast: (t: Omit<Toast, 'id'>) => void;
  removeToast: (id: number) => void;
}

const Ctx = createContext<ToastCtx>({ toasts: [], addToast: () => {}, removeToast: () => {} });
let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, dispatch] = useReducer((state: Toast[], action: { type: 'add'; toast: Toast } | { type: 'remove'; id: number }) => {
    if (action.type === 'add') return [...state, action.toast];
    return state.filter((t) => t.id !== action.id);
  }, []);

  const addToast = useCallback((t: Omit<Toast, 'id'>) => {
    const id = nextId++;
    dispatch({ type: 'add', toast: { ...t, id } });
    if (t.type !== 'error') {
      setTimeout(() => dispatch({ type: 'remove', id }), 4000);
    }
  }, []);

  const removeToast = useCallback((id: number) => dispatch({ type: 'remove', id }), []);

  const icons = { success: CheckCircle, error: XCircle, warning: AlertTriangle, info: Info };
  const colors = {
    success: '#00ff88', error: '#f85149', warning: '#e3b341', info: '#58a6ff',
  };

  return (
    <Ctx.Provider value={{ toasts, addToast, removeToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((t) => {
          const Icon = icons[t.type];
          return (
            <div
              key={t.id}
              className="pointer-events-auto flex items-start gap-3 px-4 py-3 rounded border min-w-72 max-w-sm"
              style={{ background: '#161b22', borderColor: colors[t.type], borderLeftWidth: 3 }}
            >
              <Icon size={16} style={{ color: colors[t.type], marginTop: 2, flexShrink: 0 }} />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium" style={{ color: '#e6edf3' }}>{t.title}</p>
                {t.message && <p className="text-xs mt-0.5" style={{ color: '#8b949e' }}>{t.message}</p>}
              </div>
              <button onClick={() => removeToast(t.id)} className="text-[#8b949e] hover:text-white">
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}

export function useToast() {
  return useContext(Ctx);
}
