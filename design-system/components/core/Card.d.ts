import * as React from 'react';

export interface CardProps {
  /** Optional header title rendered as .card-title. */
  title?: React.ReactNode;
  /** Right-aligned header content (buttons, counts, badges). */
  actions?: React.ReactNode;
  /** Alias for `actions`. */
  headerRight?: React.ReactNode;
  /** Prevent vertical stretch in grids (.card-fit / align-self:start). */
  fit?: boolean;
  className?: string;
  children?: React.ReactNode;
}

/**
 * Bordered surface panel — the default content container. Depth comes from a
 * 1px border on a raised background, not shadow.
 * @startingPoint section="Core" subtitle="Card — bordered surface panel" viewport="700x220"
 */
export function Card(props: CardProps): JSX.Element;
