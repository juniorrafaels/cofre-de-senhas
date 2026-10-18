import { KeyboardEvent, useMemo, useState } from "react";
import { X } from "lucide-react";
import type { Tag } from "../../types";
import { useTranslation } from "../../i18n";

interface Props {
  value: string[];
  onChange: (tags: string[]) => void;
  suggestions: Tag[];
}

export function TagPicker({ value, onChange, suggestions }: Props) {
  const { t } = useTranslation();
  const [input, setInput] = useState("");
  const [open, setOpen] = useState(false);

  const normalizedValue = value.map((v) => v.toLowerCase());

  const filtered = useMemo(() => {
    const q = input.trim().toLowerCase();
    return suggestions
      .filter((t) => !normalizedValue.includes(t.name.toLowerCase()))
      .filter((t) => !q || t.name.toLowerCase().includes(q))
      .slice(0, 8);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [suggestions, input, value]);

  function addTag(name: string) {
    const trimmed = name.trim();
    if (!trimmed) return;
    if (normalizedValue.includes(trimmed.toLowerCase())) return;
    onChange([...value, trimmed]);
    setInput("");
  }

  function removeTag(name: string) {
    onChange(value.filter((t) => t !== name));
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addTag(input);
    } else if (e.key === "Backspace" && !input && value.length > 0) {
      removeTag(value[value.length - 1]);
    }
  }

  return (
    <div className="relative">
      <div className="flex flex-wrap gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-2">
        {value.map((tag) => (
          <span key={tag} className="flex items-center gap-1 rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs text-[var(--color-text)]">
            {tag}
            <button type="button" onClick={() => removeTag(tag)} className="hover:opacity-70">
              <X size={11} />
            </button>
          </span>
        ))}
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          placeholder={value.length === 0 ? t("ui.tagPicker.addPlaceholder") : ""}
          className="min-w-[100px] flex-1 bg-transparent text-sm outline-none"
        />
      </div>

      {open && (filtered.length > 0 || input.trim()) && (
        <div className="absolute z-10 mt-1 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-1 shadow-lg">
          {filtered.map((tag) => (
            <button
              key={tag.id}
              type="button"
              onMouseDown={(e) => {
                e.preventDefault();
                addTag(tag.name);
              }}
              className="block w-full px-3 py-1.5 text-left text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
            >
              {tag.name}
            </button>
          ))}
          {input.trim() && !suggestions.some((t) => t.name.toLowerCase() === input.trim().toLowerCase()) && (
            <button
              type="button"
              onMouseDown={(e) => {
                e.preventDefault();
                addTag(input);
              }}
              className="block w-full px-3 py-1.5 text-left text-sm text-[var(--color-accent)] hover:bg-[var(--color-surface-hover)]"
            >
              {t("ui.tagPicker.createOption", { value: input.trim() })}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
