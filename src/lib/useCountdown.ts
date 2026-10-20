import { useEffect, useRef, useState } from "react";

/**
 * Contagem regressiva baseada em um PRAZO (relógio de parede), não em "subtrair 1 a cada tick":
 * se a aba/janela for suspensa ou o timer atrasar, o valor mostrado se corrige sozinho no próximo
 * tick. A fonte da verdade do bloqueio é sempre o backend; isto só desenha o tempo restante.
 *
 * `startSeconds` é o tempo restante informado pelo backend; `resetKey` reinicia a contagem
 * (mude-o a cada nova resposta do backend, mesmo que o número seja igual). `onExpire` é chamado
 * uma única vez por contagem, quando chega a zero.
 */
export function useCountdown(startSeconds: number, resetKey: unknown, onExpire?: () => void): number {
  const [remaining, setRemaining] = useState(Math.max(0, Math.ceil(startSeconds)));
  const deadlineRef = useRef(0);
  const onExpireRef = useRef(onExpire);
  onExpireRef.current = onExpire;

  useEffect(() => {
    const initial = Math.max(0, Math.ceil(startSeconds));
    setRemaining(initial);
    if (initial <= 0) return;
    deadlineRef.current = Date.now() + initial * 1000;
    let expired = false;
    const tick = () => {
      const left = Math.max(0, Math.ceil((deadlineRef.current - Date.now()) / 1000));
      setRemaining(left);
      if (left <= 0 && !expired) {
        expired = true;
        window.clearInterval(id);
        onExpireRef.current?.();
      }
    };
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [startSeconds, resetKey]);

  return remaining;
}
