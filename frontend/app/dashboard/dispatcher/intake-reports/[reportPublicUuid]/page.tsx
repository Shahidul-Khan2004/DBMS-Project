import { redirect } from "next/navigation";

export default async function LegacyIntakeReportRedirect({
  params,
}: {
  params: Promise<{ reportPublicUuid: string }>;
}) {
  const { reportPublicUuid } = await params;
  redirect(
    `/dashboard/dispatcher/intake-reports?report=${encodeURIComponent(reportPublicUuid)}`,
  );
}
