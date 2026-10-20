import { Input, Label } from "../ui/Input";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useTranslation } from "../../i18n";

/** `true` quando o cofre exige duas senhas (política aplicada no backend; aqui só decide a UI). */
export function useDualUnlock(): boolean {
  return useSecurityStore((s) => s.gate?.dual ?? false);
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  /** Rótulo; por padrão "Segunda senha atual". */
  label?: string;
}

/**
 * Campo da SEGUNDA senha de desbloqueio atual, mostrado só quando o cofre exige duas senhas.
 * Todo formulário que reautentica a senha mestra (trocar senha, Recovery Key, perguntas de
 * segurança, backup, exclusão) o inclui para não ficar sem como confirmar a identidade.
 */
export function SecondPasswordField({ value, onChange, disabled, label }: Props) {
  const dual = useDualUnlock();
  const { t } = useTranslation();
  if (!dual) return null;
  return (
    <div>
      <Label>{label ?? t("security.currentSecondPasswordLabel")}</Label>
      <Input
        type="password"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        autoComplete="off"
        aria-label={label ?? t("security.currentSecondPasswordLabel")}
      />
    </div>
  );
}
