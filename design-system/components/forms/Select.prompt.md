Native dropdown with the product's custom chevron; powers every filter and choice field.

```jsx
<Select label="Severity" options={['All severities','Critical','High','Medium','Low']} />
<Select compact options={[{value:'overdue',label:'Overdue'},{value:'on_track',label:'On track'}]} />
```

Provide `options` (strings or `{value,label}`) or pass `<option>` children. Omit `label` for an inline filter-bar select; add `compact` for the tight variant.
