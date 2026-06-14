Labelled text or textarea field with help and error slots; focus draws the violet ring.

```jsx
<Input label="Engagement name" placeholder="Q2 External Pentest" />
<Input label="Scope" textarea help="One target per line." />
<Input label="CVSS vector" error="Invalid vector string" />
```

Set `textarea` for multi-line, `compact` for tight rows, `help` / `error` for the slots below the field. All other props pass through to the underlying element.
