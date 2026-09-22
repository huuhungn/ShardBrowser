import { create } from "zustand";
import en from "./locales/en.json";
import vi from "./locales/vi.json";

// Every piece of text a person reads lives in locales/, under a NAME rather
// than under the English text itself: `t("profileTable.name")`, not
// `t("Name")`. Rewording the English then touches one line in en.json instead
// of every call site, and the same key carries every language.
//
// A key with no entry in the chosen language falls back to English, and a key
// in no file at all renders as the key — loud on screen, which is what you
// want while a screen is being built.
//
// Adding a locale is a JSON file plus one entry in DICTS/LANG_OPTIONS, with no
// call-site churn. Most screens still hold their English inline and do not call
// t() yet, so picking another language translates what has been moved into
// locales/ and leaves the rest in English. That is the intended half-state: a
// missing key must never render as its own name to someone using the app.
export type Lang = "en" | "vi";

const DICTS: Record<Lang, Record<string, string>> = {
  en: en as Record<string, string>,
  vi: vi as Record<string, string>,
};

export const LANG_OPTIONS: { value: Lang; label: string }[] = [
  { value: "en", label: "English" },
  { value: "vi", label: "Tiếng Việt" },
];

const STORAGE_KEY = "shardx.lang";

function load(): Lang {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && v in DICTS) return v as Lang;
    return "en";
  } catch {
    return "en";
  }
}

type LangState = { lang: Lang; setLang: (v: Lang) => void };

export const useLang = create<LangState>((set) => ({
  lang: load(),
  setLang: (v) => {
    try { localStorage.setItem(STORAGE_KEY, v); } catch { /* private mode */ }
    set({ lang: v });
  },
}));

/** Look one key up. `{name}` placeholders are filled from `vars`. */
export function translate(
  lang: Lang,
  key: string,
  vars?: Record<string, string | number>,
): string {
  let out = DICTS[lang][key] ?? DICTS.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(String(v));
  }
  return out;
}

/** Inside a component. Re-renders when the language changes. */
export function useT() {
  const lang = useLang((s) => s.lang);
  return (key: string, vars?: Record<string, string | number>) => translate(lang, key, vars);
}

/** Outside React — stores, helpers, toasts. */
export const t = (key: string, vars?: Record<string, string | number>) =>
  translate(useLang.getState().lang, key, vars);
