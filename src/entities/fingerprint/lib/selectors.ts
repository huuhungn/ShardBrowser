import { useMemo } from "react";
import type { FingerprintEntry } from "../model/types";
import { useFingerprint } from "./useFingerprint";

/// Library entries grouped by OS (macOS → Windows → Linux → other).
export function useFingerprintGroups() {
    const items = useFingerprint((s) => s.items);
    return useMemo<ReadonlyArray<readonly [string, FingerprintEntry[]]>>(() => {
        const order = ["macOS", "Windows", "Linux"];
        const buckets = new Map<string, FingerprintEntry[]>();
        for (const it of items) {
            // A bucket key, not a label: the library translates it when it
            // draws the heading, so grouping stays stable across languages.
            const k = it.platform || "Other";
            if (!buckets.has(k)) buckets.set(k, []);
            buckets.get(k)!.push(it);
        }
        return [
            ...order.filter((k) => buckets.has(k)).map((k) => [k, buckets.get(k)!] as const),
            ...[...buckets.keys()].filter((k) => !order.includes(k)).map((k) => [k, buckets.get(k)!] as const),
        ];
    }, [items]);
}
