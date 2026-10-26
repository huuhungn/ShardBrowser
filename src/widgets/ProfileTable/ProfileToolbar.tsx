import {
  ImportProfilesButton,
  FromTemplateButton,
  NewProfileButton,
  ProfileFilterBar,
} from "../../features/manage-profiles";

export function ProfileToolbar() {
  return (
    // Wraps under the folder tabs if the window is narrower than it needs.
    <div className="ml-auto flex max-w-full flex-none flex-wrap items-center justify-end gap-2">
      <ProfileFilterBar />
      <ImportProfilesButton />
      <FromTemplateButton />
      <NewProfileButton />
    </div>
  );
}
