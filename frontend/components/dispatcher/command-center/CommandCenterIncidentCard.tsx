import {
  getSeverityBadgeTone,
  getSeverityCardAccent,
} from "@/components/dispatcher/incidents/severityStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

interface CommandCenterIncident {
  public_uuid: string;
  title: string;
  category_code: string;
  severity_code: string;
  status_code: string;
}

interface CommandCenterIncidentCardProps {
  incident: CommandCenterIncident;
  categoryLabel: string;
  ageLabel: string;
  onOpenDetail: (publicUuid: string) => void;
}

export function CommandCenterIncidentCard({
  incident,
  categoryLabel,
  ageLabel,
  onOpenDetail,
}: CommandCenterIncidentCardProps) {
  return (
    <article
      className={`rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm ${getSeverityCardAccent(incident.severity_code)}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={getSeverityBadgeTone(incident.severity_code)} size="compact">
          {formatBadgeLabel(incident.severity_code)}
        </Badge>
        <Badge tone={incident.status_code} size="compact">
          {formatBadgeLabel(incident.status_code)}
        </Badge>
      </div>
      <p className="mt-2 text-sm font-semibold text-slate-900">{incident.title}</p>
      <p className="mt-1 text-xs text-slate-600">{categoryLabel}</p>
      <p className="mt-1 text-xs text-slate-500">{ageLabel} active</p>
      <div className="mt-3">
        <Button
          type="button"
          variant="primary"
          size="sm"
          onClick={() => onOpenDetail(incident.public_uuid)}
        >
          Open Details
        </Button>
      </div>
    </article>
  );
}
