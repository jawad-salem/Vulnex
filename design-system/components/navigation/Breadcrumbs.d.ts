import * as React from 'react';

export interface Crumb {
  label: React.ReactNode;
  /** Link target; omit (or last item) to render as the current page. */
  href?: string;
}

export interface BreadcrumbsProps {
  items: Crumb[];
  className?: string;
}

/**
 * Page trail using the chevron separator. Sits above page headers on nested
 * views (Engagements › Acme Corp › Findings).
 */
export function Breadcrumbs(props: BreadcrumbsProps): JSX.Element;
