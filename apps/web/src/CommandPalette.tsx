import { useEffect, useRef, useState } from "react";
import { matchItems, type PaletteItem } from "./palette";

// Ctrl/Cmd+K switcher: views and recent runs, filtered as you type. Focus stays
// in the input; the arrows move the highlight, Enter opens.
export function Palette({ open, onClose, items }: {
  open: boolean;
  onClose: () => void;
  items: PaletteItem[];
}) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const matches = matchItems(items, query);

  useEffect(() => {
    if (open) {
      setQuery("");
      setIndex(0);
      inputRef.current?.focus();
    }
  }, [open]);

  const choose = (item: PaletteItem | undefined) => {
    if (!item) return;
    item.action();
    onClose();
  };

  // Unmounted when closed: a visibility transition would keep the input
  // unfocusable for its duration, and a keyboard tool opens instantly anyway.
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-center pt-[15vh]" role="dialog" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative h-fit w-[32rem] max-w-[90vw] overflow-hidden rounded-lg border border-ink-200 bg-surface shadow-xl">
        <input
          ref={inputRef}
          aria-label="Command palette search"
          placeholder="Go to a view or a recent run..."
          value={query}
          onChange={(e) => { setQuery(e.target.value); setIndex(0); }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setIndex((i) => Math.min(i + 1, matches.length - 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); }
            else if (e.key === "Enter") { e.preventDefault(); choose(matches[index]); }
            else if (e.key === "Escape") { e.preventDefault(); onClose(); }
          }}
          className="w-full border-b border-ink-100 bg-transparent px-4 py-3 text-sm text-ink-800 placeholder:text-ink-300 focus:outline-none"
        />
        <ul role="listbox" aria-label="Commands" className="max-h-72 overflow-auto py-1">
          {matches.map((m, i) => (
            <li
              key={m.id}
              role="option"
              aria-selected={i === index}
              onMouseEnter={() => setIndex(i)}
              onClick={() => choose(m)}
              className={`flex cursor-pointer items-center gap-3 px-4 py-2 text-sm ${
                i === index ? "bg-brand-50 text-ink-900" : "text-ink-700"
              }`}
            >
              <span className="truncate">{m.label}</span>
              {m.hint && <span className="ml-auto truncate text-xs text-ink-500">{m.hint}</span>}
            </li>
          ))}
          {matches.length === 0 && <li className="px-4 py-3 text-sm text-ink-500">No matches.</li>}
        </ul>
        <div className="border-t border-ink-100 px-4 py-2 text-[11px] text-ink-500">
          ↑↓ to move · Enter to open · Esc to close
        </div>
      </div>
    </div>
  );
}
