import { invoke } from "@tauri-apps/api/core";
import { convertFileSrc } from "@tauri-apps/api/core";
import { appDataDir, join } from "@tauri-apps/api/path";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { createImageRecord } from "./db";
import type { ImageRecord } from "../types";

interface ImportImageResult {
  filename: string;
  hash: string;
  original_name: string;
}

let cachedImagesDir: string | null = null;

async function getImagesDir(): Promise<string> {
  if (!cachedImagesDir) {
    const base = await appDataDir();
    cachedImagesDir = await join(base, "images");
  }
  return cachedImagesDir;
}

export async function resolveImageSrc(filename: string): Promise<string> {
  const dir = await getImagesDir();
  const fullPath = await join(dir, filename);
  return convertFileSrc(fullPath);
}

export async function pickAndImportImage(): Promise<ImageRecord | null> {
  const selected = await openFileDialog({
    title: "Selecionar imagem",
    filters: [{ name: "Imagens", extensions: ["png", "jpg", "jpeg", "webp", "gif"] }],
    multiple: false,
  });
  if (!selected || Array.isArray(selected)) return null;

  const result = await invoke<ImportImageResult>("import_image", { sourcePath: selected });
  return createImageRecord(result.filename, result.original_name, result.hash);
}

export async function deleteImageFile(filename: string): Promise<void> {
  await invoke<void>("delete_image_file", { filename });
}
