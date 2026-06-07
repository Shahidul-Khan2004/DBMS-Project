import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assertUserCanLogin } from "../src/lib/accountStatusLoginErrors.js";
import BackendError from "../src/lib/BackendError.js";
import { adminAccountStatusBodySchema } from "../src/api/validators/validationSchemas.js";

describe("account status login errors", () => {
  it("throws ACCOUNT_SUSPENDED with reason and remaining time", () => {
    const expiresAt = new Date(Date.now() + 86400000).toISOString();

    try {
      assertUserCanLogin({
        account_status: "suspended",
        account_status_reason: "Repeated confirmed malicious false reports",
        account_status_expires_at: expiresAt,
      });
      assert.fail("expected throw");
    } catch (err) {
      assert.ok(err instanceof BackendError);
      assert.equal(err.statusCode, 403);
      assert.equal(err.code, "ACCOUNT_SUSPENDED");
      assert.equal(err.message, "Account suspended");
      assert.equal(err.details.accountStatus, "suspended");
      assert.equal(
        err.details.reason,
        "Repeated confirmed malicious false reports",
      );
      assert.ok(typeof err.details.remainingSeconds === "number");
      assert.ok(err.details.remainingSeconds > 0);
    }
  });

  it("throws ACCOUNT_DISABLED with reason", () => {
    try {
      assertUserCanLogin({
        account_status: "disabled",
        account_status_reason: "Confirmed abuse",
      });
      assert.fail("expected throw");
    } catch (err) {
      assert.ok(err instanceof BackendError);
      assert.equal(err.code, "ACCOUNT_DISABLED");
      assert.equal(err.details.reason, "Confirmed abuse");
    }
  });

  it("throws ACCOUNT_PENDING_VERIFICATION", () => {
    try {
      assertUserCanLogin({ account_status: "pending_verification" });
      assert.fail("expected throw");
    } catch (err) {
      assert.equal(err.code, "ACCOUNT_PENDING_VERIFICATION");
    }
  });

  it("allows active accounts", () => {
    assert.doesNotThrow(() =>
      assertUserCanLogin({ account_status: "active" }),
    );
  });
});

describe("admin account status validation for suspend", () => {
  it("requires suspendedUntil or suspensionDays for suspend", () => {
    const result = adminAccountStatusBodySchema.safeParse({
      accountStatus: "suspended",
      reason: "Repeated malicious false reports",
    });
    assert.equal(result.success, false);
  });

  it("rejects suspendedUntil for disabled", () => {
    const result = adminAccountStatusBodySchema.safeParse({
      accountStatus: "disabled",
      reason: "Permanent disable for abuse",
      suspendedUntil: new Date(Date.now() + 86400000).toISOString(),
    });
    assert.equal(result.success, false);
  });
});
