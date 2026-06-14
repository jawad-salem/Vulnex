import * as React from 'react';

export interface ProgressBarProps {
  /** Current value. */
  value?: number;
  /** Maximum (default 100). */
  max?: number;
  /** Inline 60px table variant. */
  mini?: boolean;
  className?: string;
}

/**
 * Thin violet-filled progress track. Full-width for section progress,
 * `mini` for inline cells (methodology coverage, recon completion).
 */
export function ProgressBar(props: ProgressBarProps): JSX.Element;
