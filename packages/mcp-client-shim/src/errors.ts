// Error taxonomy shared by the client and its OAuth half. It lives in its own
// module because OAuthClientError extends ShimError, and index.ts imports the
// OAuth client: one module owning the base class keeps that a straight line
// instead of an import cycle.

export class ShimError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class ApprovalClientRequiredError extends ShimError {
  constructor(message: string) {
    super(message, "APPROVAL_CLIENT_REQUIRED");
  }
}

export class ApprovalPendingError extends ShimError {
  logicalRequestId: string;
  approvalId?: string;
  expiresAt?: string;
  constructor(message: string, logicalRequestId: string, approvalId?: string, expiresAt?: string) {
    super(message, "APPROVAL_PENDING");
    this.logicalRequestId = logicalRequestId;
    this.approvalId = approvalId;
    this.expiresAt = expiresAt;
  }
}

export class ApprovalTerminalError extends ShimError {
  status?: string;
  approvalId?: string;
  constructor(message: string, status?: string, approvalId?: string) {
    super(message, "APPROVAL_TERMINAL");
    this.status = status;
    this.approvalId = approvalId;
  }
}

export class OutcomeUnknownError extends ShimError {
  approvalId?: string;
  constructor(message: string, approvalId?: string) {
    super(message, "OUTCOME_UNKNOWN");
    this.approvalId = approvalId;
  }
}
