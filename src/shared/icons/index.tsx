/**
 * App icon set: Hugeicons free tier (stroke), wrapped so views import
 * semantic names from one place — same pattern as the dashboard. Size via
 * className (e.g. size-4) or the `size` prop; colour follows currentColor.
 * Brand marks (Shard, GitHub) stay hand-drawn.
 */
import { HugeiconsIcon } from "@hugeicons/react";
import {
  BrowserIcon,
  Route01Icon,
  ShoppingCart01Icon,
  FingerPrintIcon,
  Settings01Icon,
  Copy01Icon,
  BookOpen01Icon,
  AppleIcon,
  WindowsNewIcon,
  TerminalIcon,
  PinIcon,
  Search01Icon,
  Download04Icon,
  Upload04Icon,
  Sun01Icon,
  Moon02Icon,
  ViewIcon,
  ViewOffSlashIcon,
  Key01Icon,
  Edit02Icon,
  ArrowReloadHorizontalIcon,
  PlusSignIcon,
  Folder01Icon,
  InformationCircleIcon,
  ArrowDown01Icon,
  Delete02Icon,
  Globe02Icon,
  Clock01Icon,
  Building02Icon,
  PlayIcon as HugePlayIcon,
  StopIcon as HugeStopIcon,
  MoreVerticalIcon,
  Link04Icon,
  PauseIcon as HugePauseIcon,
  SparklesIcon,
  StarIcon,
  LockIcon,
  PuzzleIcon,
  Bookmark02Icon,
  Delete03Icon,
  ArchiveRestoreIcon,
  FilterIcon as HugeFilterIcon,
  Cancel01Icon,
  WorkflowSquare10Icon,
} from "@hugeicons/core-free-icons";
import type { ComponentProps } from "react";

type HugeiconsIconProps = ComponentProps<typeof HugeiconsIcon>;
type IconProps = Omit<HugeiconsIconProps, "icon">;

const make = (icon: HugeiconsIconProps["icon"]) =>
  function AppIcon(props: IconProps) {
    return <HugeiconsIcon icon={icon} strokeWidth={1.8} {...props} />;
  };

/* ── Navigation / section icons ── */
export const NavBrowsersIcon = make(BrowserIcon);
export const NavProxiesIcon = make(Route01Icon);
export const NavShopIcon = make(ShoppingCart01Icon);
export const NavFingerprintsIcon = make(FingerPrintIcon);
export const NavSettingsIcon = make(Settings01Icon);
export const DocsIcon = make(BookOpen01Icon);
export const NavPatchLogIcon = make(SparklesIcon);
export const NavExtensionsIcon = make(PuzzleIcon);
export const NavBookmarksIcon = make(Bookmark02Icon);
export const NavTrashIcon = make(Delete03Icon);
export const NavAutomationIcon = make(WorkflowSquare10Icon);

/* ── OS logos ── */
export const AppleOsIcon = make(AppleIcon);
export const WindowsOsIcon = make(WindowsNewIcon);
export const LinuxOsIcon = make(TerminalIcon);

/* ── Actions / affordances ── */
export const RouteIcon = make(Route01Icon);
export const SearchIcon = make(Search01Icon);
export const CopyIcon = make(Copy01Icon);
export const DownloadIcon = make(Download04Icon);
export const UploadIcon = make(Upload04Icon);
export const SunIcon = make(Sun01Icon);
export const MoonIcon = make(Moon02Icon);
export const EyeIcon = make(ViewIcon);
export const EyeOffIcon = make(ViewOffSlashIcon);
export const KeyIcon = make(Key01Icon);
export const EditIcon = make(Edit02Icon);
export const RefreshIcon = make(ArrowReloadHorizontalIcon);
export const AddIcon = make(PlusSignIcon);
export const FolderIcon = make(Folder01Icon);
export const InfoIcon = make(InformationCircleIcon);
export const StarOutlineIcon = make(StarIcon);
export const LockedIcon = make(LockIcon);
export const ChevronDownIcon = make(ArrowDown01Icon);
export const DeleteIcon = make(Delete02Icon);
export const GlobeIcon = make(Globe02Icon);
export const ClockIcon = make(Clock01Icon);
export const BuildingIcon = make(Building02Icon);
export const PinIconApp = make(PinIcon);
export const PlayIcon = make(HugePlayIcon);
export const StopIcon = make(HugeStopIcon);
export const MoreIcon = make(MoreVerticalIcon);
export const SyncIcon = make(Link04Icon);
export const RestoreIcon = make(ArchiveRestoreIcon);
export const FilterIcon = make(HugeFilterIcon);
export const CloseIcon = make(Cancel01Icon);
export const PauseIcon = make(HugePauseIcon);

export function ShardLogo() {
  return (
    <svg width="20" height="18" viewBox="0 0 20 18" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M7.1026 1.22343C6.98443 0.677185 6.2319 0.606146 6.01306 1.12057L0.0492018 15.1396C-0.195534 15.7149 0.52929 16.2093 0.978164 15.7733L7.72968 9.21451C8.29604 8.66432 8.5387 7.86224 8.37197 7.09148L7.1026 1.22343Z" fill="currentColor" />
      <path d="M11.0907 8.41685C10.2971 8.17551 9.69576 7.52597 9.5178 6.71782L8.19207 0.697569C8.07126 0.148991 8.73239 -0.226919 9.14425 0.15617L19.579 9.86215C20.024 10.2761 19.6021 11.0053 19.0201 10.8283L11.0907 8.41685Z" fill="currentColor" />
      <path d="M2.19142 17.6237C1.61701 17.7849 1.20788 17.0735 1.63752 16.6605L8.48546 10.0776C9.07995 9.50612 9.93635 9.29698 10.7283 9.52988L18.7299 11.8828C19.2823 12.0453 19.2774 12.8273 18.723 12.9829L2.19142 17.6237Z" fill="currentColor" />
    </svg>
  );
}

export function ShardMini() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
      <g clipPath="url(#clip0_1_20)">
        <path d="M5.74972 1.8432C5.65406 1.40067 5.04487 1.34312 4.86772 1.75987L0.03983 13.117C-0.15829 13.5831 0.428473 13.9836 0.791847 13.6304L6.25736 8.31696C6.71585 7.87124 6.91228 7.22145 6.77731 6.59704L5.74972 1.8432Z" fill="currentColor" />
        <path d="M8.97817 7.67076C8.33573 7.47524 7.84895 6.94903 7.70489 6.29433L6.63167 1.41719C6.53388 0.97277 7.06908 0.668236 7.40248 0.978586L15.8497 8.84163C16.2099 9.17696 15.8684 9.76774 15.3972 9.62434L8.97817 7.67076Z" fill="currentColor" />
        <path d="M1.77401 15.1294C1.30901 15.2601 0.97781 14.6837 1.32561 14.3492L6.86918 9.01617C7.35043 8.5532 8.04371 8.38377 8.68485 8.57245L15.1623 10.4786C15.6095 10.6102 15.6055 11.2437 15.1567 11.3698L1.77401 15.1294Z" fill="currentColor" />
      </g>
      <defs>
        <clipPath id="clip0_1_20">
          <rect width="16" height="16" fill="white" />
        </clipPath>
      </defs>
    </svg>
  );
}

export function GithubMark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}
