"use client";

import { ServiceCaseActivityContextPanel } from "@/components/dispatcher/service-cases/detail/ServiceCaseActivityContextPanel";
import { ServiceCaseCommunicationPanel } from "@/components/dispatcher/service-cases/detail/ServiceCaseCommunicationPanel";
import { ServiceCaseSummaryCard } from "@/components/dispatcher/service-cases/detail/ServiceCaseSummaryCard";
import type {
  OperationsServiceCase,
  ServiceCaseAssignment,
  ServiceCaseMessageResult,
  ServiceCaseResolution,
  ServiceCaseStatusHistoryItem,
} from "@/types/service-case";

type ServiceCaseWorkspaceProps = {
  serviceCase: OperationsServiceCase;
  messages: ServiceCaseMessageResult[];
  statusHistory: ServiceCaseStatusHistoryItem[];
  assignments: ServiceCaseAssignment[];
  resolution: ServiceCaseResolution | null | undefined;
  linkedIncidentPublicUuid: string | null;
  canViewOriginalReport?: boolean;
  onViewOriginalReport?: () => void;
  onSendResponse: () => void;
};

export function ServiceCaseWorkspace({
  serviceCase,
  messages,
  statusHistory,
  assignments,
  resolution,
  linkedIncidentPublicUuid,
  canViewOriginalReport = false,
  onViewOriginalReport,
  onSendResponse,
}: ServiceCaseWorkspaceProps) {
  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,55fr)_minmax(0,45fr)] xl:items-stretch xl:gap-3 xl:overflow-hidden">
      <div className="flex min-h-0 flex-col gap-3 xl:min-h-0 xl:overflow-hidden">
        <ServiceCaseSummaryCard
          className="shrink-0"
          serviceCase={serviceCase}
          assignments={assignments}
          canViewOriginalReport={canViewOriginalReport}
          onViewOriginalReport={onViewOriginalReport}
        />
        <ServiceCaseCommunicationPanel
          className="min-h-0 flex-1 xl:h-full"
          messages={messages}
          statusCode={serviceCase.status_code}
          onSendResponse={onSendResponse}
        />
      </div>
      <ServiceCaseActivityContextPanel
        className="min-h-0 flex-1 xl:h-full"
        serviceCase={serviceCase}
        statusHistory={statusHistory}
        assignments={assignments}
        resolution={resolution}
        linkedIncidentPublicUuid={linkedIncidentPublicUuid}
      />
    </div>
  );
}
