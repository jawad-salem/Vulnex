Underline tab bar for detail views (engagement, finding). Controlled or uncontrolled.

```jsx
const [tab, setTab] = React.useState('overview');
<Tabs value={tab} onChange={setTab} tabs={[
  { id:'overview', label:'Overview' },
  { id:'evidence', label:'Evidence', count:3 },
  { id:'cvss', label:'CVSS' },
]} />
```

Each tab takes `{id, label, count?}`. Render your own panels keyed off the active id; the component only manages the bar.
