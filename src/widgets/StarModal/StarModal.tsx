import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button, Modal } from "@proxyshard/shardx-ui-kit";
import { GithubMark } from "../../shared/icons";
import { GH_REPO_URL } from "../../shared/lib/utils";
import { useT } from "../../shared/i18n";

/// One-time GitHub-star prompt shown after the app first loads. Dismissal is
/// remembered in localStorage so it never nags again.
export function StarModal() {
  const t = useT();
  const [show, setShow] = useState(false);
  useEffect(() => {
    if (localStorage.getItem("shardx-star-prompt") === "done") return;
    // Let the UI settle before surfacing the prompt.
    const t = setTimeout(() => setShow(true), 700);
    return () => clearTimeout(t);
  }, []);
  const close = () => {
    localStorage.setItem("shardx-star-prompt", "done");
    setShow(false);
  };
  const star = () => {
    openUrl(GH_REPO_URL).catch(() => {});
    close();
  };
  if (!show) return null;
  return (
    <Modal open onClose={close} maxWidthClassName="max-w-[416px]">
      <div className="px-2 pb-2 pt-4 text-center">
        <div className="relative mx-auto mb-4 flex size-[58px] items-center justify-center rounded-full bg-bg-weak-50 text-text-strong-950 ring-1 ring-inset ring-stroke-soft-200">
          <GithubMark size={26} />
          <span className="absolute -top-[5px] right-[-3px] text-[19px] leading-none text-warning-base">★</span>
        </div>
        <h2 className="m-0 mb-2 text-title-h6 text-text-strong-950">Enjoying ShardX?</h2>
        <p className="m-0 mb-[22px] text-paragraph-sm text-text-sub-600">
          ShardX is provided and supported <strong>completely free</strong>. If it's
          useful to you, dropping a <strong>star on GitHub</strong> is the easiest way to
          support us — and it helps other people find the project.
        </p>
        <div className="flex justify-center gap-2.5">
          <Button variant="neutral" mode="stroke" size="small" onClick={close}>
            {t("star.maybeLater")}
          </Button>
          <Button variant="primary" mode="filled" size="small" leftIcon={<GithubMark />} onClick={star}>
            {t("star.starOnGithub")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
