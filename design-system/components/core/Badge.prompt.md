Uppercase pill conveying state — the product's primary at-a-glance signal for severity, finding status, review state and SLA.

```jsx
<Badge tone="critical">Critical</Badge>
<Badge tone="confirmed">Confirmed</Badge>
<Badge tone="approved">Approved</Badge>
<Badge tone="overdue">Overdue 3d</Badge>
```

`tone` selects color + meaning (`critical`/`high`/`medium`/`low`/`info` for severity; `open`/`confirmed`/`remediated`/`accepted`/`false_positive` for status; `draft`/`in_review`/`approved` for review; `overdue`/`due_soon`/`on_track` for SLA; plus engagement-phase and scan-state tones). Use `size="lg"` inside stat cards.
