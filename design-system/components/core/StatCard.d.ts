import * as React from 'react';

export interface StatCardProps {
  /** Uppercase label, e.g. "Active engagements". */
  label: React.ReactNode;
  /** Big mono value. */
  value: React.ReactNode;
  /** Tone class for the value: `critical` | `high` | `medium` | `low`. */
  valueTone?: 'critical' | 'high' | 'medium' | 'low';
  /** Inline color override for the value (e.g. computed risk color). */
  valueColor?: string;
  /** Optional sub-label under the value. */
  sub?: React.ReactNode;
  /** Tone for the sub-label: `high` | `critical` keyword, or a CSS color. */
  subTone?: string;
  className?: string;
}

/**
 * Dashboard KPI tile — uppercase label, oversized monospace value, optional
 * sub-label. Hover lifts the card and accents the border.
 * @startingPoint section="Core" subtitle="StatCard — dashboard KPI tile" viewport="700x150"
 */
export function StatCard(props: StatCardProps): JSX.Element;
