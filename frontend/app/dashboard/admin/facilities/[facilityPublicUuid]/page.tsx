import { redirect } from "next/navigation";
import { nationalDisasterFacilityDetailPath } from "@/lib/admin-national-disaster-routes";

export default async function AdminFacilityDetailRedirectPage({
  params,
}: {
  params: Promise<{ facilityPublicUuid: string }>;
}) {
  const { facilityPublicUuid } = await params;
  redirect(nationalDisasterFacilityDetailPath(facilityPublicUuid));
}
