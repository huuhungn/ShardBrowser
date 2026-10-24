import { cn } from "@proxyshard/shardx-ui-kit";
import { tagColor, useTags } from "../lib/useTags";

export function TagChip({ name, className, children }: {
  name: string;
  className?: string;
  /** Trailing control, e.g. a remove button. */
  children?: React.ReactNode;
}) {
  const tags = useTags((s) => s.tags);
  return (
    <span className={cn("tag-chip", className)} data-color={tagColor(name, tags)} title={name}>
      <span className="truncate">{name}</span>
      {children}
    </span>
  );
}
