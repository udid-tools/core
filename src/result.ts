import { toUdidToolsError, type UdidToolsError, type UdidToolsWarning } from "./errors.js";

/**
 * Non-throwing operation result. Successful values may include actionable,
 * non-fatal warnings; failures contain one sanitized typed error.
 */
export type Result<T> =
  | {
      readonly ok: true;
      readonly value: T;
      readonly warnings: readonly UdidToolsWarning[];
    }
  | {
      readonly ok: false;
      readonly error: UdidToolsError;
    };

export function success<T>(value: T, warnings: readonly UdidToolsWarning[] = []): Result<T> {
  return { ok: true, value, warnings };
}

export function failure<T = never>(error: unknown): Result<T> {
  return { ok: false, error: toUdidToolsError(error) };
}

export async function resultify<T>(operation: () => Promise<T>): Promise<Result<T>> {
  try {
    return success(await operation());
  } catch (error) {
    return failure(error);
  }
}

export function unwrapResult<T>(result: Result<T>): T {
  if (!result.ok) {
    throw result.error;
  }

  return result.value;
}
