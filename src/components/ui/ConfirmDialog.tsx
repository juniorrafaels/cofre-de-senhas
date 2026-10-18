import { Modal } from "./Modal";
import { Button } from "./Button";
import { useTranslation } from "../../i18n";

interface Props {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ open, title, message, confirmLabel, danger, onConfirm, onCancel }: Props) {
  const { t } = useTranslation();
  return (
    <Modal open={open} onClose={onCancel} title={title} width="sm">
      <p className="text-sm text-[var(--color-text-muted)]">{message}</p>
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          {t("common.cancel")}
        </Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>
          {confirmLabel ?? t("ui.confirmDialogDefault")}
        </Button>
      </div>
    </Modal>
  );
}
