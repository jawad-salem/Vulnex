Dashboard KPI tile — uppercase label, oversized mono value, optional sub-label. Hover lifts the card and accents the border.

```jsx
<div className="stats-grid">
  <StatCard label="Risk score" value="7.8" valueColor="#f09236" sub="High" subTone="#f09236" />
  <StatCard label="Critical / High" value="1" valueTone="critical" sub="2 high" subTone="high" />
</div>
```

Wrap several in a `.stats-grid`. `valueTone` accepts `critical|high|medium|low`; `valueColor` takes an arbitrary color for computed scores.
