import { create } from "zustand";
import type { ToastAction, ToastItem } from "../types";
import { safeUiError } from "../lib/utils";

/// Global toast queue (zustand). `toast.ok/err/info` can be called from
/// anywhere — including non-React code — via the store's static API.
type ToastState = {
  items: ToastItem[];
  push: (kind: ToastItem["kind"], text: string, action?: ToastAction) => void;
  dismiss: (id: number) => void;
};

let seq = 0;

export const useToastStore = create<ToastState>((set) => ({
  items: [],
  push: (kind, text, action) => {
    const id = ++seq;
    set((s) => ({ items: [...s.items, { id, kind, text, action }] }));
    setTimeout(() => {
      set((s) => ({ items: s.items.filter((t) => t.id !== id) }));
    }, 5500);
  },
  dismiss: (id) => set((s) => ({ items: s.items.filter((t) => t.id !== id) })),
}));

export const toast = {
  /** `action` adds a button to the toast, as Undo; pressing it closes the toast. */
  ok: (t: string, action?: ToastAction) => useToastStore.getState().push("ok", t, action),
  /**
   * Error toast.
   *
   * Redaction happens here rather than at each call site: most callers pass a
   * raw exception, and a backend error can carry a bearer token, a proxy
   * password or key material. Sanitising centrally means a new call site
   * cannot forget.
   */
  err: (t: unknown) => useToastStore.getState().push("err", safeUiError(t)),
  info: (t: string) => useToastStore.getState().push("info", t),
};
