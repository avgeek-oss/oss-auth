/** What an app id looks like: `posted`, `mill`, `vitalog`. */
export const APP_ID_PATTERN = /^[a-z][a-z0-9]{0,31}$/;

/**
 * Throws a `TypeError` unless `app` matches {@link APP_ID_PATTERN}. A bad app
 * id is a programming error, not a configuration problem.
 */
export function assertAppId(app: string): void {
  if (!APP_ID_PATTERN.test(app))
    throw new TypeError(
      `App id "${app}" must be 1 to 32 lowercase letters or digits, starting with a letter.`,
    );
}
