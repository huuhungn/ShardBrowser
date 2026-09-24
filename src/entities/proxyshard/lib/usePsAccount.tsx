import { create } from "zustand";
import { t } from "../../../shared/i18n";
import { toast } from "../../../shared/lib/toast";
import { PsMe } from "../model/types";
import { psGetKey, psSetKey, psMe } from "../model/api";
import { safeUiError } from "../../../shared/lib/utils";

export type PsStatus = "idle" | "checking" | "ok" | "err";

export type PsAccountStore = {
    // null = still loading the saved key from disk.
    key: string | null;
    me: PsMe | null;
    status: PsStatus;
    err: string;
    keyLoaded: boolean;

    init: () => Promise<void>;
    refreshMe: () => Promise<void>;
    saveKey: (next: string) => Promise<void>;
};

export const usePsAccount = create<PsAccountStore>((set, get) => ({
    key: null,
    me: null,
    status: "idle",
    err: "",
    keyLoaded: false,

    init: async () => {
        if (get().keyLoaded) return;
        try {
            const k = await psGetKey();
            set({ key: k, keyLoaded: true });
            if (k) get().refreshMe();
            else set({ status: "idle" });
        } catch {
            set({ key: "", keyLoaded: true });
        }
    },
    // Validate the saved key against user-api.proxyshard.com and pull the wallet.
    refreshMe: async () => {
        set({ status: "checking", err: "" });
        try {
            const m = await psMe();
            set({ me: m, status: "ok" });
        } catch (e) {
            set({ me: null, status: "err", err: String(e) });
        }
    },
    saveKey: async (next) => {
        const value = next.trim();
        try {
            await psSetKey(value);
            set({ key: value });
            toast.ok(t("ps.apiKeySaved"));
            if (value) get().refreshMe();
            else set({ me: null, status: "idle" });
        } catch (e) { toast.err(safeUiError(e)); }
    },
}));
