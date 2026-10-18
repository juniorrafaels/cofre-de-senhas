import { create } from "zustand";

export interface ToastItem {
  id: number;
  message: string;
  kind: "success" | "error" | "info";
}

interface ToastStore {
  toasts: ToastItem[];
  push: (message: string, kind?: ToastItem["kind"]) => void;
  remove: (id: number) => void;
}

let nextId = 1;

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  push: (message, kind = "info") => {
    const id = nextId++;
    set((state) => ({ toasts: [...state.toasts, { id, message, kind }] }));
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }));
    }, 2500);
  },
  remove: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));
