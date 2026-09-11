type Translate = (key: string) => string;

export function localizeAuthError(error: string, t: Translate) {
  const normalized = error.trim().toLowerCase();

  switch (normalized) {
    case "logout_incomplete":
      return t("hermesDesktop.logoutIncomplete");
    default:
      return error;
  }
}
