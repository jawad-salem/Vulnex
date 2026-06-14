import * as React from 'react';

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps {
  /** Optional field label; when omitted the bare <select> is returned. */
  label?: React.ReactNode;
  id?: string;
  /** Options as {value,label} objects or plain strings. */
  options?: Array<SelectOption | string>;
  value?: string;
  defaultValue?: string;
  onChange?: (e: React.ChangeEvent<HTMLSelectElement>) => void;
  /** Smaller filter-bar variant (.form-input--compact). */
  compact?: boolean;
  className?: string;
  children?: React.ReactNode;
}

/**
 * Native select styled with the product's custom chevron. Used everywhere for
 * filters (severity, status, SLA) and form choices.
 */
export function Select(props: SelectProps): JSX.Element;
