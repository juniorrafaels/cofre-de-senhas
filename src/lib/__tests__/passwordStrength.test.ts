import { describe, expect, it } from "vitest";
import { coarseLevel, evaluatePasswordStrength, levelForScore, MAX_STRENGTH_SCORE } from "../passwordStrength";

describe("evaluatePasswordStrength — critérios idênticos aos da senha mestra", () => {
  it("empty and trivially short passwords are the weakest", () => {
    expect(evaluatePasswordStrength("")).toEqual({ score: 0, level: "veryWeak" });
    expect(evaluatePasswordStrength("abc")).toEqual({ score: 0, level: "veryWeak" });
  });

  it("scores one point per criterion (>=8, >=12, mixed case, digit, symbol)", () => {
    expect(evaluatePasswordStrength("abcdefgh").score).toBe(1); // só tamanho >= 8
    expect(evaluatePasswordStrength("abcdefgh").level).toBe("weak");
    expect(evaluatePasswordStrength("Abcdefgh").score).toBe(2); // + maiúscula/minúscula
    expect(evaluatePasswordStrength("Abcdefg1").score).toBe(3); // + dígito
    expect(evaluatePasswordStrength("Abcdef1!").score).toBe(4); // + símbolo
    expect(evaluatePasswordStrength("Abcdefghij1!").score).toBe(5); // + tamanho >= 12
    expect(evaluatePasswordStrength("Abcdefghij1!").level).toBe("veryStrong");
    expect(MAX_STRENGTH_SCORE).toBe(5);
  });

  it("maps scores to five readable levels", () => {
    expect([0, 1, 2, 3, 4, 5].map(levelForScore)).toEqual(["veryWeak", "weak", "fair", "fair", "strong", "veryStrong"]);
  });

  it("the three-level grouping keeps the original master-password thresholds (<=1 weak, 2-3 fair, >=4 strong)", () => {
    const original = (score: number) => (score <= 1 ? "weak" : score <= 3 ? "fair" : "strong");
    for (let score = 0; score <= 5; score++) {
      expect(coarseLevel(levelForScore(score))).toBe(original(score));
    }
  });

  it("is a pure function of the password: same input, same output, nothing stored", () => {
    const a = evaluatePasswordStrength("Senha-Fictícia-123");
    const b = evaluatePasswordStrength("Senha-Fictícia-123");
    expect(a).toEqual(b);
  });
});
