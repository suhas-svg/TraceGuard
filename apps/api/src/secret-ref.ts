import { readFileSync } from "node:fs";

// §7.3/§7.4: the database and the control API carry only a reference to an
// upstream credential. The value is resolved at the point of use, and a
// missing or unreadable reference fails closed instead of calling without
// authentication.
//
// Supported v1 references:
//   env:NAME          environment variable in the gateway process
//   file:/abs/path    file readable by the gateway (Docker/Kubernetes secret)
//
// A bare value is deliberately rejected so an operator cannot fall back to
// storing the credential in the database by accident.
const ENV_REF = /^env:([A-Za-z_][A-Za-z0-9_]*)$/;
const FILE_REF = /^file:(.+)$/;

export class SecretRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretRefError";
  }
}

export function secretRefIssue(ref: string | null | undefined): string | null {
  if (ref === null || ref === undefined || ref === "") return null;
  if (ref.length > 512) return "secret reference is too long";
  if (ENV_REF.test(ref)) return null;
  const file = FILE_REF.exec(ref);
  if (file && file[1].trim().length > 0) return null;
  return "secret reference must be env:NAME or file:/absolute/path";
}

export function resolveSecretRef(ref: string | null | undefined): string | null {
  if (ref === null || ref === undefined || ref === "") return null;

  const env = ENV_REF.exec(ref);
  if (env) {
    const value = process.env[env[1]];
    if (!value?.trim()) {
      throw new SecretRefError(`secret reference ${ref} is not set in the gateway environment`);
    }
    return value;
  }

  const file = FILE_REF.exec(ref);
  if (file) {
    let value: string;
    try {
      value = readFileSync(file[1], "utf8").replace(/\r?\n$/, "");
    } catch {
      throw new SecretRefError(`secret reference ${ref} could not be read`);
    }
    if (!value.trim()) {
      throw new SecretRefError(`secret reference ${ref} is empty`);
    }
    return value;
  }

  throw new SecretRefError(`secret reference ${ref} is not supported`);
}
