import { listPublicDemoAccounts } from "../../services/demoAccountsPublicService.js";

export async function getPublicDemoAccounts(_req, res) {
  res.status(200).json(listPublicDemoAccounts());
}
