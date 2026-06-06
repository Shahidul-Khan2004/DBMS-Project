import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import { createUser, findUserByEmail } from "../repositories/userRepo.js";
import {
  assignRoleToUser,
  findRoleByCode,
  hasRoleAssignment,
} from "../repositories/rbacRepo.js";
import { ROLE_CODES } from "./rbacService.js";

const DEMO_DISPATCHER = {
  email: "dispatcher@niers.test",
  fullName: "Demo Dispatcher",
  phoneNumber: "01700000004",
};

export async function bootstrapDemoDispatcher() {
  const password = process.env.DEMO_DISPATCHER_PASSWORD;
  if (!password) {
    return;
  }

  if (password.length < 8) {
    console.warn(
      "Skipping demo dispatcher bootstrap. DEMO_DISPATCHER_PASSWORD must be at least 8 characters.",
    );
    return;
  }

  const dispatcherRole = await findRoleByCode(ROLE_CODES.DISPATCHER);
  if (!dispatcherRole) {
    console.warn("Skipping demo dispatcher bootstrap. dispatcher role not found.");
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  let user = await findUserByEmail(DEMO_DISPATCHER.email);

  if (!user) {
    await createUser({
      publicUuid: randomUUID(),
      email: DEMO_DISPATCHER.email,
      fullName: DEMO_DISPATCHER.fullName,
      phoneNumber: DEMO_DISPATCHER.phoneNumber,
      passwordHash,
    });
    user = await findUserByEmail(DEMO_DISPATCHER.email);
  }

  if (!user) {
    return;
  }

  const assigned = await hasRoleAssignment({
    userId: user.id,
    roleCode: ROLE_CODES.DISPATCHER,
  });
  if (!assigned) {
    await assignRoleToUser({
      userId: user.id,
      roleId: dispatcherRole.id,
      assignedByUserId: null,
    });
  }

  console.log(`Bootstrapped demo dispatcher: ${DEMO_DISPATCHER.email}`);
}
