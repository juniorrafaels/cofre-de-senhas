import { describe, expect, it } from "vitest";
import { BADGE_VALIDITY_DAYS, FUTURE_TOLERANCE_MS, formatLastLogin, getUpdateBadge, parseConfirmation } from "../accountBadge";

const DAY = 24 * 60 * 60 * 1000;
const CONFIRMED = "2026-01-10T08:30:00Z";
const confirmedMs = Date.parse(CONFIRMED);

describe("getUpdateBadge — validade de 90 dias", () => {
  it("uses 90 days", () => {
    expect(BADGE_VALIDITY_DAYS).toBe(90);
  });

  it("is valid right after the confirmation and shows the days left", () => {
    const state = getUpdateBadge(CONFIRMED, confirmedMs);
    expect(state.status).toBe("valid");
    if (state.status === "valid") expect(state.daysLeft).toBe(90);
  });

  it("is valid until the last second and expires exactly at 90 x 24 h", () => {
    const expiry = confirmedMs + 90 * DAY;
    const lastSecond = getUpdateBadge(CONFIRMED, expiry - 1000);
    expect(lastSecond.status).toBe("valid");
    if (lastSecond.status === "valid") expect(lastSecond.daysLeft).toBe(1);

    const atExpiry = getUpdateBadge(CONFIRMED, expiry);
    expect(atExpiry.status).toBe("expired");
    expect(getUpdateBadge(CONFIRMED, expiry + 400 * DAY).status).toBe("expired");
  });

  it("is not affected by time zone or daylight saving: the same instant written in other offsets expires together", () => {
    const boundary = Date.parse("2026-03-01T03:00:00Z") + 90 * DAY;
    for (const written of ["2026-03-01T00:00:00-03:00", "2026-03-01T03:00:00Z", "2026-03-01T10:00:00+07:00"]) {
      expect(getUpdateBadge(written, boundary - 1000).status).toBe("valid");
      expect(getUpdateBadge(written, boundary).status).toBe("expired");
    }
  });

  it("missing, empty, malformed or date-only values never yield a valid badge", () => {
    for (const bad of [null, undefined, "", "   ", "ontem", "2026-13-45T00:00:00Z", "2026-01-10", "2026-01-10 08:30:00"]) {
      expect(getUpdateBadge(bad, confirmedMs + DAY).status).toBe("none");
    }
    expect(parseConfirmation("lixo")).toBeNull();
  });

  it("dates in the future beyond the small clock tolerance are invalid, not valid", () => {
    const now = confirmedMs;
    expect(getUpdateBadge(new Date(now + 2 * DAY).toISOString(), now).status).toBe("none");
    expect(getUpdateBadge(new Date(now + FUTURE_TOLERANCE_MS + 1000).toISOString(), now).status).toBe("none");
    expect(getUpdateBadge(new Date(now + FUTURE_TOLERANCE_MS - 1000).toISOString(), now).status).toBe("valid");
  });
});

describe("formatLastLogin", () => {
  it("shows a calendar date as is, without shifting a day because of the time zone", () => {
    expect(formatLastLogin("2026-02-10", "en-US")).toBe(new Date(2026, 1, 10).toLocaleDateString("en-US"));
    expect(formatLastLogin("2026-12-31", "pt-BR")).toBe(new Date(2026, 11, 31).toLocaleDateString("pt-BR"));
  });

  it("returns an empty string for missing or invalid values", () => {
    expect(formatLastLogin(null, "en-US")).toBe("");
    expect(formatLastLogin("", "en-US")).toBe("");
    expect(formatLastLogin("nao-e-data", "en-US")).toBe("");
  });
});
