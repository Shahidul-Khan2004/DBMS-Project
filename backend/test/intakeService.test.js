import assert from "node:assert/strict";
import { describe, it } from "node:test";

describe("intake validation expectations", () => {
  it("createIntakeReportSchema rejects missing required fields", async () => {
    const { createIntakeReportSchema } = await import(
      "../src/api/validators/validationSchemas.js"
    );

    const result = createIntakeReportSchema.safeParse({});
    assert.equal(result.success, false);
    assert.ok(result.error?.issues?.length > 0);
  });

  it("classifyEmergency999Schema requires severityCode", async () => {
    const { classifyEmergency999Schema } = await import(
      "../src/api/validators/validationSchemas.js"
    );

    const result = classifyEmergency999Schema.safeParse({});
    assert.equal(result.success, false);
    const fields = result.error?.issues?.map((i) => i.path.join(".")) ?? [];
    assert.ok(fields.some((f) => f.includes("severityCode")));
  });
});
