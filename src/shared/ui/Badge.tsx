/// Generic coloured chip. The UI kit's `Badge` is now a fixed order-status
/// component, so the app keeps its own small chip for proxy types, counts,
/// connection state, etc. Styled with the kit's design tokens so it reads as
/// native to the system.
import type { HTMLAttributes } from "react";
import { cn } from "@proxyshard/shardx-ui-kit";

export type BadgeColor = "success" | "error" | "warning" | "primary" | "information" | "gray";
export type BadgeVariant = "filled" | "light" | "lighter" | "stroke";
export type BadgeSize = "small" | "medium";

export type BadgeProps = HTMLAttributes<HTMLSpanElement> & {
  color?: BadgeColor;
  variant?: BadgeVariant;
  size?: BadgeSize;
  dot?: boolean;
};

const soft: Record<BadgeColor, string> = {
  success: "text-[var(--color-success)] bg-[var(--color-success-background)]",
  error: "text-[var(--color-error)] bg-[var(--color-error-background)]",
  warning: "text-[var(--color-warning)] bg-[var(--color-warning-background)]",
  primary: "text-primary-base bg-[var(--color-primary-alpha-16)]",
  information: "text-[var(--color-information-base)] bg-[var(--color-information-weak)]",
  gray: "text-[var(--color-text-sub-600)] bg-[var(--color-bg-weak-50)]",
};

const stroke: Record<BadgeColor, string> = {
  success: "text-[var(--color-success)] border-[var(--color-success)]",
  error: "text-[var(--color-error)] border-[var(--color-error)]",
  warning: "text-[var(--color-warning)] border-[var(--color-warning)]",
  primary: "text-primary-base border-[var(--color-primary-base)]",
  information: "text-[var(--color-information-base)] border-[var(--color-information-base)]",
  gray: "text-[var(--color-text-sub-600)] border-[var(--color-stroke-soft-200)]",
};

export default function Badge({
  color = "gray",
  variant = "filled",
  size = "medium",
  dot = false,
  className,
  children,
  ...rest
}: BadgeProps) {
  const isStroke = variant === "stroke";
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center text-center gap-1 rounded-md font-medium whitespace-nowrap",
        size === "small" ? "px-1.5 py-0.5 text-[11px] leading-4" : "px-2 py-0.5 text-label-xs",
        isStroke ? cn("border bg-transparent", stroke[color]) : soft[color],
        className,
      )}
      {...rest}
    >
      {dot && <span className="size-1.5 shrink-0  text-center rounded-full bg-current" />}
      {children}
    </span>
  );
}
