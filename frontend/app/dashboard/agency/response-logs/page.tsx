import { redirect } from "next/navigation";

export default function AgencyResponseLogsRedirectPage() {
  redirect("/dashboard/agency/field-updates");
}
