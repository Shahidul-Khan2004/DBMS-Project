import type { ReactNode } from "react";

type AdminPageHeaderProps = {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  compact?: boolean;
};

export function AdminPageHeader({
  title,
  subtitle,
  action,
  compact = false,
}: AdminPageHeaderProps) {
  return (
    <header
      className={`flex shrink-0 flex-wrap items-start justify-between ${
        compact ? "gap-2" : "gap-3"
      }`}
    >
      <div className="min-w-0">
        <h2
          className={`font-semibold text-slate-900 ${
            compact ? "text-lg" : "text-xl"
          }`}
        >
          {title}
        </h2>
        {subtitle ? (
          <p
            className={`mt-0.5 text-slate-600 ${
              compact
                ? "line-clamp-1 text-xs"
                : "text-sm"
            }`}
          >
            {subtitle}
          </p>
        ) : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </header>
  );
}
