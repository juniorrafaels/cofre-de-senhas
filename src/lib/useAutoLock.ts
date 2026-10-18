import { useEffect, useRef } from "react";

const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"] as const;

/**
 * Bloqueio por inatividade (Fase 2 do hardening — ver SECURITY_AUDIT_PHASE_2.md).
 *
 * Além do `setTimeout` de inatividade (que já bloqueia mesmo com a janela minimizada, pois
 * continua contando independente de foco), este hook guarda o horário real da última atividade
 * (`Date.now()`, relógio de parede) e o reconfere sempre que o documento volta a ficar visível
 * ou a janela recupera o foco. Isso cobre o caso em que o sistema operacional suspende/hiberna:
 * timers JS não avançam durante a suspensão, mas ao retomar o Chromium (motor do WebView2/
 * WebKitGTK usados pelo Tauri) dispara `visibilitychange`/`focus` de qualquer forma — então,
 * mesmo que o `setTimeout` original não tenha dado conta sozinho, o cofre bloqueia assim que a
 * janela volta a ser vista, se o tempo configurado já tiver passado.
 */
export function useAutoLock(minutes: number, onTimeout: () => void) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef(Date.now());
  const lockedRef = useRef(false);

  useEffect(() => {
    if (!minutes || minutes <= 0) return;
    const timeoutMs = minutes * 60 * 1000;

    const clearTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = null;
    };

    const lockNow = () => {
      if (lockedRef.current) return;
      lockedRef.current = true;
      clearTimer();
      onTimeout();
    };

    const reset = () => {
      lastActivityRef.current = Date.now();
      lockedRef.current = false;
      clearTimer();
      timerRef.current = setTimeout(lockNow, timeoutMs);
    };

    // Reconfere o relógio de parede (não confia só no setTimeout ter sobrevivido a uma
    // suspensão do SO) sempre que a janela volta a ficar visível/em foco.
    const recheckElapsedTime = () => {
      if (lockedRef.current) return;
      const elapsed = Date.now() - lastActivityRef.current;
      if (elapsed >= timeoutMs) {
        lockNow();
      } else {
        clearTimer();
        timerRef.current = setTimeout(lockNow, timeoutMs - elapsed);
      }
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") recheckElapsedTime();
    };

    reset();
    for (const event of ACTIVITY_EVENTS) window.addEventListener(event, reset);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", recheckElapsedTime);

    return () => {
      clearTimer();
      for (const event of ACTIVITY_EVENTS) window.removeEventListener(event, reset);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("focus", recheckElapsedTime);
    };
  }, [minutes, onTimeout]);
}
