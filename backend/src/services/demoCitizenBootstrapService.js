import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import { createUser, findUserByEmail } from "../repositories/userRepo.js";
import {
  assignRoleToUser,
  findRoleByCode,
  hasRoleAssignment,
} from "../repositories/rbacRepo.js";
import { ROLE_CODES } from "./rbacService.js";

const DEMO_CITIZENS = [
  {
    email: "citizen.rahima@niers.test",
    fullName: "Rahima Begum",
    phoneNumber: "01710000001",
  },
  {
    email: "citizen.karim@niers.test",
    fullName: "Abdul Karim",
    phoneNumber: "01710000002",
  },
  {
    email: "citizen.farhana@niers.test",
    fullName: "Farhana Akter",
    phoneNumber: "01710000003",
  },
  {
    email: "citizen.rubel@niers.test",
    fullName: "Rubel Hossain",
    phoneNumber: "01710000004",
  },
  {
    email: "citizen.shamim@niers.test",
    fullName: "Shamim Ahmed",
    phoneNumber: "01710000005",
  },
];

export async function bootstrapDemoCitizens() {
  const password = process.env.DEMO_CITIZEN_PASSWORD;
  if (!password) {
    return;
  }

  if (password.length < 8) {
    console.warn(
      "Skipping demo citizen bootstrap. DEMO_CITIZEN_PASSWORD must be at least 8 characters.",
    );
    return;
  }

  const citizenRole = await findRoleByCode(ROLE_CODES.CITIZEN);
  if (!citizenRole) {
    console.warn("Skipping demo citizen bootstrap. citizen role not found.");
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);

  for (const citizen of DEMO_CITIZENS) {
    let user = await findUserByEmail(citizen.email);

    if (!user) {
      await createUser({
        publicUuid: randomUUID(),
        email: citizen.email,
        fullName: citizen.fullName,
        phoneNumber: citizen.phoneNumber,
        passwordHash,
      });
      user = await findUserByEmail(citizen.email);
    }

    if (!user) {
      continue;
    }

    const assigned = await hasRoleAssignment({
      userId: user.id,
      roleCode: ROLE_CODES.CITIZEN,
    });
    if (!assigned) {
      await assignRoleToUser({
        userId: user.id,
        roleId: citizenRole.id,
        assignedByUserId: null,
      });
    }
  }

  console.log(
    "Bootstrapped demo citizens (citizen.rahima/karim/farhana/rubel/shamim@niers.test).",
  );
}
