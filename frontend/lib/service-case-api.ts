import { apiGet } from "@/lib/api";
import type { ServiceCaseMessagesResponse } from "@/types/service-case";

export function getOperationsServiceCaseMessages(publicUuid: string) {
  return apiGet<ServiceCaseMessagesResponse>(
    `/operations/service-cases/${publicUuid}/messages`,
  );
}
