import { assignRoleToUserByPublicId } from "../../services/rbacService.js";

export async function assignRoleToUser(req, res) {
  const { userId } = req.params;
  const { roleCode } = req.body;

  const result = await assignRoleToUserByPublicId({
    targetUserPublicId: userId,
    roleCode,
    assignedByUserId: req.actorUserId ?? null,
  });

  res.status(200).json({
    message: "Role assigned successfully",
    userId: result.userPublicId,
    roleCode: result.roleCode,
  });
}
