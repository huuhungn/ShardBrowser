import type { ReactNode } from "react";

/// One empty-state layout for every list: icon tile, title, explanation and
/// optional actions. `card` adds the surface for lists that have no table
/// frame of their own.
export function EmptyState({ icon, title, body, actions, card = false }: {
  icon: ReactNode;
  title: ReactNode;
  body?: ReactNode;
  actions?: ReactNode;
  card?: boolean;
}) {
  return (
    <div
      className={
        "flex flex-col items-center gap-2.5 px-6 py-14 text-center" +
        (card ? " rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200" : "")
      }
    >
      <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
        {icon}
      </div>
      <h2 className="m-0 text-label-sm text-text-strong-950">{title}</h2>
      {body && <p className="m-0 max-w-[460px] text-paragraph-sm text-text-sub-600">{body}</p>}
      {actions && <div className="mt-2 flex gap-2">{actions}</div>}
    </div>
  );
}
