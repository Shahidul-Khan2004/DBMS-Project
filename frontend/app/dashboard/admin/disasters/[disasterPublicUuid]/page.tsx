import { redirect } from "next/navigation";
import { nationalDisasterDetailPath } from "@/lib/admin-national-disaster-routes";

export default async function AdminDisasterDetailRedirectPage({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  const { disasterPublicUuid } = await params;
  redirect(nationalDisasterDetailPath(disasterPublicUuid));
}
