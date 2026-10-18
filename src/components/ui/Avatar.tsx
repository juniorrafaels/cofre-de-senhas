import { useEffect, useState } from "react";
import { resolveImageSrc } from "../../lib/images";
import { getImageById } from "../../lib/db";
import { PlatformIcon } from "./PlatformIcon";

interface Props {
  imageId?: number | null;
  platformIcon?: string | null;
  platformLogoImageId?: number | null;
  size?: number;
  className?: string;
}

export function Avatar({ imageId, platformIcon = null, platformLogoImageId = null, size = 36, className }: Props) {
  const [src, setSrc] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setSrc(null);
    if (imageId) {
      getImageById(imageId).then((record) => {
        if (cancelled || !record) return;
        resolveImageSrc(record.filename).then((url) => {
          if (!cancelled) setSrc(url);
        });
      });
    }
    return () => {
      cancelled = true;
    };
  }, [imageId]);

  return (
    <div
      className={`flex shrink-0 items-center justify-center overflow-hidden rounded-lg bg-[var(--color-surface-hover)] ${className ?? ""}`}
      style={{ width: size, height: size }}
    >
      {src ? (
        <img src={src} alt="" className="h-full w-full object-cover" />
      ) : (
        <PlatformIcon icon={platformIcon} logoImageId={platformLogoImageId} size={Math.round(size * 0.5)} />
      )}
    </div>
  );
}
