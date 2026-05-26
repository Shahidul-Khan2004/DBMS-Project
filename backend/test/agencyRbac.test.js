import assert from "node:assert/strict";
import { describe, it } from "node:test";
import BackendError from "../src/lib/BackendError.js";
import {
  ROLE_CODES,
  assignRoleToUserByPublicId,
} from "../src/services/rbacService.js";

describe("agency representative RBAC", () => {
  it("blocks assigning agency_representative outside admin onboard routes", async () => {
    await assert.rejects(
      () =>
        assignRoleToUserByPublicId({
          targetUserPublicId: "00000000-0000-4000-8000-000000000001",
          roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
          assignedByUserId: null,
        }),
      (error) => {
        assert.ok(error instanceof BackendError);
        assert.equal(error.statusCode, 403);
        assert.equal(error.code, "ROLE_ASSIGNMENT_NOT_ALLOWED");
        return true;
      },
    );
  });
});
