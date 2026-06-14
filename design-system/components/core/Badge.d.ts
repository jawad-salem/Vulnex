import * as React from 'react';

/** Every badge tone defined in the Vulnex stylesheet. */
export type BadgeTone =
  | 'critical' | 'high' | 'medium' | 'low' | 'info'
  | 'open' | 'confirmed' | 'remediated' | 'false_positive' | 'accepted'
  | 'not_retested' | 'fixed' | 'partial' | 'still_present'
  | 'overdue' | 'due_soon' | 'on_track'
  | 'draft' | 'in_review' | 'approved' | 'changes_requested'
  | 'planning' | 'recon' | 'scanning' | 'exploitation' | 'post_exploitation'
  | 'reporting' | 'completed' | 'cancelled'
  | 'not_started' | 'in_progress' | 'not_applicable'
  | 'pending' | 'running' | 'failed';

export interface BadgeProps {
  /** Color + meaning. Matches a `.badge-<tone>` class. Default `info`. */
  tone?: BadgeTone;
  /** `lg` for stat-card-scale badges. */
  size?: 'lg';
  className?: string;
  children?: React.ReactNode;
}

/**
 * Uppercase pill conveying state. The single most-used signal in the product —
 * severity, status, review, SLA. Keep labels to 1–2 words.
 * @startingPoint section="Core" subtitle="Badges — severity, status, review, SLA" viewport="700x200"
 */
export function Badge(props: BadgeProps): JSX.Element;
