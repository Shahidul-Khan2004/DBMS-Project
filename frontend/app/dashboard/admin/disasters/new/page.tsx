import { redirect } from "next/navigation";
import { nationalDisasterDeclarePath } from "@/lib/admin-national-disaster-routes";

export default function AdminDeclareDisasterRedirectPage() {
  redirect(nationalDisasterDeclarePath());
}
