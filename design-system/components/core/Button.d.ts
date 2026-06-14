import * as React from 'react';

export interface ButtonProps {
  /** Visual style. `primary` = filled violet, `secondary` = bordered, `danger` = red outline. */
  variant?: 'primary' | 'secondary' | 'danger';
  /** `md` (default) or compact `sm`. */
  size?: 'md' | 'sm';
  /** Render as a link to this URL instead of a <button>. */
  href?: string;
  /** Leading icon node (e.g. an inline SVG / Lucide element). */
  icon?: React.ReactNode;
  /** Trailing icon node. */
  iconRight?: React.ReactNode;
  disabled?: boolean;
  /** Shows a trailing spinner and blocks interaction. */
  loading?: boolean;
  /** Stretch to container width and center contents. */
  fullWidth?: boolean;
  type?: 'button' | 'submit' | 'reset';
  className?: string;
  children?: React.ReactNode;
}

/**
 * Primary action control for Vulnex. Use `primary` for the single main action
 * per view, `secondary` for everything else, `danger` for destructive ops.
 * @startingPoint section="Core" subtitle="Buttons — primary, secondary, danger" viewport="700x150"
 */
export function Button(props: ButtonProps): JSX.Element;
