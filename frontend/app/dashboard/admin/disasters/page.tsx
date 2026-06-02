import { redirect } from "next/navigation";
import { nationalDisasterLandingPath } from "@/lib/admin-national-disaster-routes";

export default function AdminDisastersRedirectPage() {
  redirect(nationalDisasterLandingPath());
}
