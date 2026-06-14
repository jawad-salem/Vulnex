import * as React from 'react';

export interface TabItem {
  id: string;
  label: React.ReactNode;
  /** Optional count pill rendered after the label. */
  count?: number;
}

export interface TabsProps {
  tabs: TabItem[];
  /** Controlled active tab id. */
  value?: string;
  /** Uncontrolled initial tab id. */
  defaultValue?: string;
  onChange?: (id: string) => void;
  className?: string;
}

/**
 * Underline tab bar used on engagement and finding detail views (Overview /
 * Evidence / CVSS / Retest / Review / Comments / Details).
 * @startingPoint section="Navigation" subtitle="Tabs & breadcrumbs" viewport="700x140"
 */
export function Tabs(props: TabsProps): JSX.Element;
