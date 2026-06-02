import { redirect } from "next/navigation";
import { nationalDisasterFacilitiesPath } from "@/lib/admin-national-disaster-routes";

export default function AdminFacilitiesRedirectPage() {
  redirect(nationalDisasterFacilitiesPath());
}
