/**
 * Resultado de uma tentativa de buscar um campo cifrado (senha, notes, 2FA, propriedade
 * sensível) via um command específico do Rust. Fase 2 do hardening: campos cifrados falham de
 * forma segura — nunca assumimos silenciosamente que uma falha significa "texto puro legado".
 * A migração automática no unlock já garante que dado legado é convertido; se ainda assim a
 * descriptografia falhar aqui, é sinal de corrupção/adulteração, não de formato legado.
 *
 * Fase 4 (SECURITY_AUDIT_PHASE_4.md): generalizado de "decifra este ciphertext" para "chame este
 * command específico" — não existe mais um `decrypt_secret` genérico para envolver aqui.
 */
export type FetchResult<T> = { ok: true; value: T } | { ok: false };

export async function tryFetch<T>(fetcher: () => Promise<T>): Promise<FetchResult<T>> {
  try {
    const value = await fetcher();
    return { ok: true, value };
  } catch {
    return { ok: false };
  }
}
