import { assignRoleToUserByPublicId } from "../../services/rbacService.js";
import { updateMyProfile } from "../../services/userService.js";

export async function assignRoleToUser(req, res) {
  const params = req.validated?.params ?? req.params;
  const { userId } = params;
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

export async function updateMyProfileController(req, res) {
  const body = req.validated?.body ?? req.body;
  const user = await updateMyProfile(req.actorUserId, body);
  res.status(200).json({ message: "Profile updated successfully", user });
}