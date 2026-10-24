import {
  BulkActionsBar,
  ImportProfilesButton,
  FromTemplateButton,
  NewProfileButton,
  ProfileFilterBar,
} from "../../features/manage-profiles";

export function ProfileToolbar() {
  return (
    // Wraps under the folder tabs, then onto more lines, when a selection
    // makes it wider than the window (minWidth 1280) leaves room for.
    <div className="ml-auto flex max-w-full flex-none flex-wrap items-center justify-end gap-2">
      <BulkActionsBar />
      <ProfileFilterBar />
      <ImportProfilesButton />
      <FromTemplateButton />
      <NewProfileButton />
    </div>
  );
}
