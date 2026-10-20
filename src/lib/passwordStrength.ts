// Avaliador de força de senha ÚNICO do app: usado pela senha mestra (CreateMasterPassword) e pelas
// senhas das contas (AccountForm). Os critérios são exatamente os que a senha mestra já usava
// (tamanho >= 8 e >= 12, maiúscula+minúscula, dígito, símbolo) — só foram extraídos para cá para
// não haver dois avaliadores com critérios contraditórios.
//
// Roda 100% local e puro: nenhuma senha é enviada a serviço externo, gravada, logada ou incluída
// em mensagens. É uma heurística de composição, NÃO uma medida de entropia real: "Aaaaaaaa1!aaa"
// pontua alto e uma frase longa só de minúsculas pontua baixo. A interface só informa; nunca
// altera a senha nem impede salvar.

export type StrengthLevel = "veryWeak" | "weak" | "fair" | "strong" | "veryStrong";

export interface PasswordStrength {
  /** 0 a 5 (um ponto por critério atendido). */
  score: number;
  level: StrengthLevel;
}

export const MAX_STRENGTH_SCORE = 5;

export function evaluatePasswordStrength(password: string): PasswordStrength {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  return { score, level: levelForScore(score) };
}

export function levelForScore(score: number): StrengthLevel {
  if (score <= 0) return "veryWeak";
  if (score === 1) return "weak";
  if (score <= 3) return "fair";
  if (score === 4) return "strong";
  return "veryStrong";
}

/**
 * Agrupamento em 3 níveis usado pela tela de criação da senha mestra (Fraca / Razoável / Forte):
 * os mesmos limiares de antes (<=1 fraca, 2-3 razoável, >=4 forte), derivados dos 5 níveis acima.
 */
export function coarseLevel(level: StrengthLevel): "weak" | "fair" | "strong" {
  if (level === "veryWeak" || level === "weak") return "weak";
  if (level === "fair") return "fair";
  return "strong";
}
