import * as React from 'react';

export interface AvatarProps {
  /** Full name — used for initials and deterministic color if not overridden. */
  name?: string;
  /** Override the computed initials. */
  initials?: string;
  /** Override the computed background color (hex). */
  color?: string;
  /** Pixel diameter. Default 28 (matches .avatar-sm). */
  size?: number;
  className?: string;
}

/**
 * Round initials chip with a deterministic per-user color. Used in the sidebar
 * footer, table user cells and comment threads.
 */
export function Avatar(props: AvatarProps): JSX.Element;
