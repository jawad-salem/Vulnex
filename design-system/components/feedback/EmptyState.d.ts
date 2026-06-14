import * as React from 'react';

export interface EmptyStateProps {
  /** Icon node, shown in the rounded accent tile. */
  icon?: React.ReactNode;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  /** Action button(s), centered below the copy. */
  action?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}

/**
 * Centered empty / zero-data state with an accent icon tile, title, subtitle
 * and optional call-to-action. Used for empty finding lists, no engagements, etc.
 */
export function EmptyState(props: EmptyStateProps): JSX.Element;
