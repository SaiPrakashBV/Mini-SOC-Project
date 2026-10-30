/** Horizontal bar list: [{ key, count }] with optional color class per key. */
export default function BarList({ items, colorFor, onSelect, empty = 'No data' }) {
  if (!items || items.length === 0) return <div className="empty">{empty}</div>;
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <ul className="barlist">
      {items.map((item) => (
        <li key={item.key} onClick={onSelect ? () => onSelect(item.key) : undefined}
            className={onSelect ? 'clickable' : ''}>
          <span className="barlist-label" title={item.key}>{item.label ?? item.key}</span>
          <span className="barlist-track">
            <span className={`barlist-fill ${colorFor ? colorFor(item.key) : ''}`}
                  style={{ width: `${(item.count / max) * 100}%` }} />
          </span>
          <span className="barlist-count">{item.count}</span>
        </li>
      ))}
    </ul>
  );
}
