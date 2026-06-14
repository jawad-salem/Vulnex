import * as React from 'react';

export interface InputProps {
  /** Uppercase field label. */
  label?: React.ReactNode;
  id?: string;
  /** HTML input type. Ignored when `textarea`. */
  type?: string;
  /** Render a <textarea> instead of <input>. */
  textarea?: boolean;
  /** Muted helper text under the field. */
  help?: React.ReactNode;
  /** Red error message under the field. */
  error?: React.ReactNode;
  /** Smaller padding/size variant. */
  compact?: boolean;
  placeholder?: string;
  value?: string;
  defaultValue?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
  className?: string;
}

/**
 * Labelled text / textarea field with help + error slots. Focus draws the
 * violet ring. Wraps .form-group + .form-input.
 * @startingPoint section="Forms" subtitle="Input, Select & form controls" viewport="700x260"
 */
export function Input(props: InputProps): JSX.Element;
