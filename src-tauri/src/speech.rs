// The voices a profile says it has installed.
//
// Why this exists
// ---------------
// The bundled Windows presets all carry the same two local SAPI voices,
// `Microsoft Irina` and `Microsoft Pavel`, both ru-RU, with Irina as the
// default. They were captured on one Russian donor machine and copied across
// all 120 presets. Every other spoofed field follows the profile: timezone,
// navigator.language, Accept-Language, the ICU locale, the browser's own UI
// language. The voice list does not.
//
// That is a contradiction a page can read with no permission at all:
//
//     speechSynthesis.getVoices()
//       .filter(v => v.localService)        -> [Irina ru-RU, Pavel ru-RU]
//     navigator.language                    -> "en-US"
//
// A Windows machine whose UI language is English does not ship Russian SAPI
// voices and nothing else. The pair names the donor, and it names it the same
// way on every profile built from these presets -- so it also links them to
// each other.
//
// What this module does
// ----------------------
// Replaces the LOCAL voices with the ones Windows actually installs for the
// profile's own locale, and leaves the network voices alone. The network list
// (Google *) comes from the browser and is the same everywhere, so rewriting
// it would be inventing evidence rather than correcting it.
//
// The tables below are the voices Windows 10/11 installs with a given UI
// language, in the order SAPI enumerates them. They are deliberately short:
// a machine with extra language packs is a rarer machine than one without,
// and a list that claims more than the default install is as distinctive as
// the Russian one it replaces.

use serde_json::{json, Value};

/// A local voice as the engine reports it.
struct Voice {
    name: &'static str,
    lang: &'static str,
}

/// The default SAPI voices for a Windows UI language.
///
/// The first entry is the one SAPI makes default. Returns None for a locale
/// whose voice names are not known, so the caller can leave the list alone
/// rather than guess -- a wrong name is worse than an unchanged one.
fn windows_voices(locale: &str) -> Option<&'static [Voice]> {
    // Match on the language subtag first, then let a few region-specific
    // lists override it, because es-ES and es-MX ship different voices.
    let lower = locale.to_ascii_lowercase();
    let lang = lower.split(['-', '_']).next().unwrap_or("");

    const EN_US: &[Voice] = &[
        Voice {
            name: "Microsoft David - English (United States)",
            lang: "en-US",
        },
        Voice {
            name: "Microsoft Zira - English (United States)",
            lang: "en-US",
        },
    ];
    const EN_GB: &[Voice] = &[
        Voice {
            name: "Microsoft Hazel - English (Great Britain)",
            lang: "en-GB",
        },
        Voice {
            name: "Microsoft Susan - English (Great Britain)",
            lang: "en-GB",
        },
    ];
    const RU: &[Voice] = &[
        Voice {
            name: "Microsoft Irina - Russian (Russia)",
            lang: "ru-RU",
        },
        Voice {
            name: "Microsoft Pavel - Russian (Russia)",
            lang: "ru-RU",
        },
    ];
    const DE: &[Voice] = &[
        Voice {
            name: "Microsoft Hedda - German (Germany)",
            lang: "de-DE",
        },
        Voice {
            name: "Microsoft Stefan - German (Germany)",
            lang: "de-DE",
        },
    ];
    const FR: &[Voice] = &[
        Voice {
            name: "Microsoft Hortense - French (France)",
            lang: "fr-FR",
        },
        Voice {
            name: "Microsoft Paul - French (France)",
            lang: "fr-FR",
        },
    ];
    const ES_ES: &[Voice] = &[
        Voice {
            name: "Microsoft Helena - Spanish (Spain)",
            lang: "es-ES",
        },
        Voice {
            name: "Microsoft Laura - Spanish (Spain)",
            lang: "es-ES",
        },
    ];
    const ES_MX: &[Voice] = &[
        Voice {
            name: "Microsoft Sabina - Spanish (Mexico)",
            lang: "es-MX",
        },
        Voice {
            name: "Microsoft Raul - Spanish (Mexico)",
            lang: "es-MX",
        },
    ];
    const IT: &[Voice] = &[
        Voice {
            name: "Microsoft Elsa - Italian (Italy)",
            lang: "it-IT",
        },
        Voice {
            name: "Microsoft Cosimo - Italian (Italy)",
            lang: "it-IT",
        },
    ];
    const PT_BR: &[Voice] = &[
        Voice {
            name: "Microsoft Maria - Portuguese (Brazil)",
            lang: "pt-BR",
        },
        Voice {
            name: "Microsoft Daniel - Portuguese (Brazil)",
            lang: "pt-BR",
        },
    ];
    const PL: &[Voice] = &[
        Voice {
            name: "Microsoft Paulina - Polish (Poland)",
            lang: "pl-PL",
        },
        Voice {
            name: "Microsoft Adam - Polish (Poland)",
            lang: "pl-PL",
        },
    ];
    const NL: &[Voice] = &[Voice {
        name: "Microsoft Frank - Dutch (Netherlands)",
        lang: "nl-NL",
    }];
    const JA: &[Voice] = &[
        Voice {
            name: "Microsoft Haruka - Japanese (Japan)",
            lang: "ja-JP",
        },
        Voice {
            name: "Microsoft Ichiro - Japanese (Japan)",
            lang: "ja-JP",
        },
    ];
    const KO: &[Voice] = &[Voice {
        name: "Microsoft Heami - Korean (Korean)",
        lang: "ko-KR",
    }];
    const ZH_CN: &[Voice] = &[
        Voice {
            name: "Microsoft Huihui - Chinese (Simplified, PRC)",
            lang: "zh-CN",
        },
        Voice {
            name: "Microsoft Yaoyao - Chinese (Simplified, PRC)",
            lang: "zh-CN",
        },
        Voice {
            name: "Microsoft Kangkang - Chinese (Simplified, PRC)",
            lang: "zh-CN",
        },
    ];
    const ZH_TW: &[Voice] = &[
        Voice {
            name: "Microsoft Hanhan - Chinese (Traditional, Taiwan)",
            lang: "zh-TW",
        },
        Voice {
            name: "Microsoft Yating - Chinese (Traditional, Taiwan)",
            lang: "zh-TW",
        },
        Voice {
            name: "Microsoft Zhiwei - Chinese (Traditional, Taiwan)",
            lang: "zh-TW",
        },
    ];
    const TR: &[Voice] = &[Voice {
        name: "Microsoft Tolga - Turkish (Turkey)",
        lang: "tr-TR",
    }];
    const VI: &[Voice] = &[Voice {
        name: "Microsoft An - Vietnamese (Vietnam)",
        lang: "vi-VN",
    }];
    const ID: &[Voice] = &[Voice {
        name: "Microsoft Andika - Indonesian (Indonesia)",
        lang: "id-ID",
    }];
    const CS: &[Voice] = &[Voice {
        name: "Microsoft Jakub - Czech (Czech Republic)",
        lang: "cs-CZ",
    }];
    const SV: &[Voice] = &[Voice {
        name: "Microsoft Bengt - Swedish (Sweden)",
        lang: "sv-SE",
    }];

    // Region-specific lists that differ from their language default.
    match lower.as_str() {
        "en-gb" => return Some(EN_GB),
        "es-mx" | "es-us" | "es-ar" | "es-co" | "es-cl" => return Some(ES_MX),
        "zh-tw" | "zh-hk" | "zh-mo" => return Some(ZH_TW),
        _ => {}
    }

    Some(match lang {
        "en" => EN_US,
        "ru" => RU,
        "de" => DE,
        "fr" => FR,
        "es" => ES_ES,
        "it" => IT,
        "pt" => PT_BR,
        "pl" => PL,
        "nl" => NL,
        "ja" => JA,
        "ko" => KO,
        "zh" => ZH_CN,
        "tr" => TR,
        "vi" => VI,
        "id" => ID,
        "cs" => CS,
        "sv" => SV,
        _ => return None,
    })
}

/// Rewrite the profile's LOCAL voices to match its locale.
///
/// Network voices are left untouched: they come from the browser, not the
/// machine, and are identical everywhere. A locale with no known voice list,
/// or a profile with no speech block, is left alone.
pub fn align_voices_with_locale(cfg: &mut serde_json::Map<String, Value>, locale: &str) {
    let Some(voices) = windows_voices(locale) else {
        return;
    };
    let Some(list) = cfg
        .get_mut("speech")
        .and_then(|v| v.as_object_mut())
        .and_then(|s| s.get_mut("voices"))
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    // Nothing local declared means nothing to correct -- and adding voices to
    // a profile that deliberately has none would be a change of its own.
    if !list
        .iter()
        .any(|v| v["local_service"].as_bool() == Some(true))
    {
        return;
    }

    let network: Vec<Value> = list
        .iter()
        .filter(|v| v["local_service"].as_bool() != Some(true))
        .cloned()
        .collect();

    let mut rebuilt: Vec<Value> = voices
        .iter()
        .enumerate()
        .map(|(i, v)| {
            json!({
                "name": v.name,
                "lang": v.lang,
                "local_service": true,
                // SAPI makes the first installed voice the default, and the
                // engine reports exactly one default.
                "is_default": i == 0,
            })
        })
        .collect();

    // A network voice must not keep a default flag it inherited from the donor
    // list, or the profile reports two defaults where a real browser reports
    // one.
    rebuilt.extend(network.into_iter().map(|mut v| {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("is_default".into(), Value::Bool(false));
        }
        v
    }));

    *list = rebuilt;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The donor list every bundled win-* preset ships with.
    fn donor_profile() -> serde_json::Map<String, Value> {
        json!({
            "speech": {
                "voices": [
                    { "name": "Microsoft Irina - Russian (Russia)", "lang": "ru-RU",
                      "local_service": true, "is_default": true },
                    { "name": "Microsoft Pavel - Russian (Russia)", "lang": "ru-RU",
                      "local_service": true, "is_default": false },
                    { "name": "Google US English", "lang": "en-US",
                      "local_service": false, "is_default": false },
                    { "name": "Google Deutsch", "lang": "de-DE",
                      "local_service": false, "is_default": false }
                ]
            }
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn voices(cfg: &serde_json::Map<String, Value>) -> &Vec<Value> {
        cfg["speech"]["voices"].as_array().unwrap()
    }

    #[test]
    fn an_english_profile_stops_claiming_russian_voices() {
        let mut cfg = donor_profile();
        align_voices_with_locale(&mut cfg, "en-US");

        let local: Vec<&str> = voices(&cfg)
            .iter()
            .filter(|v| v["local_service"] == json!(true))
            .map(|v| v["lang"].as_str().unwrap())
            .collect();
        assert_eq!(
            local,
            vec!["en-US", "en-US"],
            "local voices must match the profile"
        );
        assert!(
            !voices(&cfg)
                .iter()
                .any(|v| v["name"].as_str().unwrap().contains("Irina")),
            "the donor's voice must be gone",
        );
    }

    #[test]
    fn the_network_voices_are_left_as_the_browser_reports_them() {
        let mut cfg = donor_profile();
        align_voices_with_locale(&mut cfg, "fr-FR");

        let network: Vec<&str> = voices(&cfg)
            .iter()
            .filter(|v| v["local_service"] == json!(false))
            .map(|v| v["name"].as_str().unwrap())
            .collect();
        assert_eq!(network, vec!["Google US English", "Google Deutsch"]);
    }

    #[test]
    fn exactly_one_voice_is_the_default() {
        let mut cfg = donor_profile();
        align_voices_with_locale(&mut cfg, "de-DE");

        let defaults: Vec<&Value> = voices(&cfg)
            .iter()
            .filter(|v| v["is_default"] == json!(true))
            .collect();
        assert_eq!(
            defaults.len(),
            1,
            "a real browser reports one default voice"
        );
        assert_eq!(defaults[0]["lang"], json!("de-DE"));
    }

    #[test]
    fn a_russian_profile_keeps_the_voices_it_should_have() {
        let mut cfg = donor_profile();
        align_voices_with_locale(&mut cfg, "ru-RU");

        assert!(voices(&cfg)
            .iter()
            .any(|v| v["name"].as_str().unwrap().contains("Irina")));
    }

    #[test]
    fn a_locale_with_no_known_voices_is_left_untouched() {
        let mut cfg = donor_profile();
        let before = cfg.clone();
        // Icelandic ships no default SAPI voice; guessing a name would be
        // worse than leaving the donor's list in place.
        align_voices_with_locale(&mut cfg, "is-IS");
        assert_eq!(cfg, before);
    }

    #[test]
    fn a_profile_that_declares_no_local_voices_gains_none() {
        let mut cfg = json!({
            "speech": { "voices": [
                { "name": "Google US English", "lang": "en-US",
                  "local_service": false, "is_default": false }
            ] }
        })
        .as_object()
        .unwrap()
        .clone();
        let before = cfg.clone();
        align_voices_with_locale(&mut cfg, "en-US");
        assert_eq!(
            cfg, before,
            "an empty local list is a choice, not an omission"
        );
    }

    #[test]
    fn a_profile_without_a_speech_block_is_not_given_one() {
        let mut cfg = json!({ "navigator": { "language": "en-US" } })
            .as_object()
            .unwrap()
            .clone();
        align_voices_with_locale(&mut cfg, "en-US");
        assert!(cfg.get("speech").is_none());
    }

    #[test]
    fn regional_spanish_gets_its_own_voices() {
        let mut cfg = donor_profile();
        align_voices_with_locale(&mut cfg, "es-MX");
        assert!(voices(&cfg)
            .iter()
            .any(|v| v["name"].as_str().unwrap().contains("Sabina")));

        let mut spain = donor_profile();
        align_voices_with_locale(&mut spain, "es-ES");
        assert!(voices(&spain)
            .iter()
            .any(|v| v["name"].as_str().unwrap().contains("Helena")));
    }
}
