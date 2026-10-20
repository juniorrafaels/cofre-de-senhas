/**
 * Formata uma espera em segundos como "1 h 5 min 3 s" (partes zeradas são omitidas). As
 * abreviações h/min/s são as mesmas nos três idiomas da interface.
 */
export function formatWait(totalSeconds: number): string {
  const secs = Math.max(0, Math.ceil(totalSeconds));
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const parts: string[] = [];
  if (h) parts.push(`${h} h`);
  if (m) parts.push(`${m} min`);
  if (s || parts.length === 0) parts.push(`${s} s`);
  return parts.join(" ");
}
