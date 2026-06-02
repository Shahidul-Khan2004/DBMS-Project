"use client";

import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { RELIEF_ITEM_OPTIONS } from "@/lib/disaster-operations-format";

export type ReliefLineItemRow = {
  reliefItemCode: string;
  quantity: string;
};

type ReliefLineItemsEditorProps = {
  items: ReliefLineItemRow[];
  onChange: (items: ReliefLineItemRow[]) => void;
  quantityLabel: string;
  disabled?: boolean;
};

export function ReliefLineItemsEditor({
  items,
  onChange,
  quantityLabel,
  disabled = false,
}: ReliefLineItemsEditorProps) {
  const updateRow = (index: number, patch: Partial<ReliefLineItemRow>) => {
    onChange(
      items.map((row, i) => (i === index ? { ...row, ...patch } : row)),
    );
  };

  const addRow = () => {
    onChange([
      ...items,
      { reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" },
    ]);
  };

  const removeRow = (index: number) => {
    if (items.length <= 1) return;
    onChange(items.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-3">
      {items.map((row, index) => (
        <div
          key={`relief-item-${index}`}
          className="grid gap-2 rounded-lg border border-slate-100 p-3 sm:grid-cols-[1fr_120px_auto]"
        >
          <div>
            <FieldLabel htmlFor={`relief-item-code-${index}`} required>
              Item
            </FieldLabel>
            <select
              id={`relief-item-code-${index}`}
              value={row.reliefItemCode}
              onChange={(e) =>
                updateRow(index, { reliefItemCode: e.target.value })
              }
              className={triageFieldClassName}
              disabled={disabled}
            >
              {RELIEF_ITEM_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <FieldLabel htmlFor={`relief-item-qty-${index}`} required>
              {quantityLabel}
            </FieldLabel>
            <input
              id={`relief-item-qty-${index}`}
              type="number"
              min={1}
              step={1}
              value={row.quantity}
              onChange={(e) => updateRow(index, { quantity: e.target.value })}
              className={triageFieldClassName}
              disabled={disabled}
            />
          </div>
          <div className="flex items-end">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => removeRow(index)}
              disabled={disabled || items.length <= 1}
            >
              Remove
            </Button>
          </div>
        </div>
      ))}
      <Button type="button" variant="outline" size="sm" onClick={addRow} disabled={disabled}>
        Add item
      </Button>
    </div>
  );
}

export function parseReliefLineItems(
  items: ReliefLineItemRow[],
): { reliefItemCode: string; quantity: number }[] | null {
  const parsed: { reliefItemCode: string; quantity: number }[] = [];
  for (const row of items) {
    const qty = Number(row.quantity);
    if (!row.reliefItemCode.trim() || !Number.isFinite(qty) || qty <= 0) {
      return null;
    }
    parsed.push({ reliefItemCode: row.reliefItemCode, quantity: qty });
  }
  return parsed.length > 0 ? parsed : null;
}
