import { describe, expect, it } from "vitest";
import { formatWait } from "../duration";

describe("formatWait", () => {
  it("formats every step of the lockout table", () => {
    expect(formatWait(15)).toBe("15 s");
    expect(formatWait(30)).toBe("30 s");
    expect(formatWait(60)).toBe("1 min");
    expect(formatWait(300)).toBe("5 min");
    expect(formatWait(1800)).toBe("30 min");
    expect(formatWait(3600)).toBe("1 h");
    expect(formatWait(7200)).toBe("2 h");
    expect(formatWait(14400)).toBe("4 h");
  });

  it("combines units and rounds fractions up", () => {
    expect(formatWait(3725)).toBe("1 h 2 min 5 s");
    expect(formatWait(90)).toBe("1 min 30 s");
    expect(formatWait(14.2)).toBe("15 s");
  });

  it("never shows negative or empty text", () => {
    expect(formatWait(0)).toBe("0 s");
    expect(formatWait(-5)).toBe("0 s");
  });
});
