import { ReactNode } from "react";
import { ShieldOff } from "lucide-react";

interface Props {
  icon?: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
}

export function EmptyState({ icon, title, description, action }: Props) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 py-20 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--color-surface-hover)] text-[var(--color-text-muted)]">
        {icon ?? <ShieldOff size={26} />}
      </div>
      <h3 className="text-base font-semibold text-[var(--color-text)]">{title}</h3>
      <p className="max-w-sm text-sm text-[var(--color-text-muted)]">{description}</p>
      {action}
    </div>
  );
}
