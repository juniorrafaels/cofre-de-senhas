import { CheckCircle2, Info, XCircle } from "lucide-react";
import { useToastStore } from "../../store/useToastStore";

const ICONS = {
  success: <CheckCircle2 size={16} className="text-[var(--color-success)]" />,
  error: <XCircle size={16} className="text-[var(--color-danger)]" />,
  info: <Info size={16} className="text-[var(--color-accent)]" />,
};

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);

  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-[100] flex flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="animate-fade-in pointer-events-auto flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3.5 py-2.5 text-sm text-[var(--color-text)] shadow-lg"
        >
          {ICONS[toast.kind]}
          {toast.message}
        </div>
      ))}
    </div>
  );
}
