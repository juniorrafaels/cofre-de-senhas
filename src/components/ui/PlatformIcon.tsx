import { useEffect, useState } from "react";
import { getImageById } from "../../lib/db";
import { resolveImageSrc } from "../../lib/images";

interface Props {
  icon: string | null;
  logoImageId?: number | null;
  size?: number;
  className?: string;
}

export function PlatformIcon({ icon, logoImageId, size = 18, className }: Props) {
  const [logoSrc, setLogoSrc] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLogoSrc(null);
    if (logoImageId) {
      getImageById(logoImageId).then((record) => {
        if (cancelled || !record) return;
        resolveImageSrc(record.filename).then((url) => {
          if (!cancelled) setLogoSrc(url);
        });
      });
    }
    return () => {
      cancelled = true;
    };
  }, [logoImageId]);

  if (logoSrc) {
    return (
      <span
        className={`inline-block shrink-0 overflow-hidden rounded ${className ?? ""}`}
        style={{ width: size, height: size }}
      >
        <img src={logoSrc} alt="" className="h-full w-full object-cover" />
      </span>
    );
  }

  return (
    <span className={className} style={{ fontSize: size, lineHeight: 1 }}>
      {icon || "🌐"}
    </span>
  );
}
