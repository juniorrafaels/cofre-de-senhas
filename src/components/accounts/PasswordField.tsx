import { useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { Input } from "../ui/Input";
import { useCopySecret } from "../../lib/useCopy";
import { clipboardCommands } from "../../lib/tauri";
import { useTranslation } from "../../i18n";

interface Props {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  placeholder?: string;
}

export function PasswordField({ value, onChange, readOnly, placeholder }: Props) {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);
  // Senha digitada no formulário: copia como segredo (fora do Win+V, com limpeza automática).
  const copySecret = useCopySecret();

  return (
    <div className="relative">
      <Input
        type={visible ? "text" : "password"}
        value={value}
        readOnly={readOnly}
        placeholder={placeholder}
        onChange={(e) => onChange?.(e.target.value)}
        className="pr-16"
      />
      <div className="absolute right-1.5 top-1/2 flex -translate-y-1/2 items-center gap-0.5">
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
          title={visible ? t("accounts.passwordField.hide") : t("accounts.passwordField.show")}
        >
          {visible ? <EyeOff size={15} /> : <Eye size={15} />}
        </button>
        <button
          type="button"
          onClick={() => copySecret(!!value, (secs) => clipboardCommands.copySecret(value, secs), t("accounts.passwordField.label"))}
          className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
          title={t("accounts.passwordField.copy")}
        >
          <Copy size={15} />
        </button>
      </div>
    </div>
  );
}
