import * as React from 'react';

export interface AlertProps {
  /** Color + intent. */
  tone?: 'success' | 'error' | 'warning' | 'info';
  /** Show the × dismiss button. */
  dismissible?: boolean;
  onClose?: () => void;
  className?: string;
  children?: React.ReactNode;
}

/**
 * Inline message / toast banner. Auto-dismissing toasts in the product slide in
 * from the top; reuse this for static inline messages too.
 * @startingPoint section="Feedback" subtitle="Alerts, progress & empty states" viewport="700x220"
 */
export function Alert(props: AlertProps): JSX.Element;
