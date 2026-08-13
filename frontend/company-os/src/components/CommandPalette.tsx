import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./Icon";
import { useResizablePanel } from "./ResizablePanel";

export interface PaletteCommand {
  id: string;
  label: string;
  detail: string;
  keywords: string;
  run: () => void;
}

interface CommandPaletteProps {
  commands: PaletteCommand[];
  onClose: () => void;
}

export function CommandPalette({ commands, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const resize = useResizablePanel({
    id: "command-palette",
    anchor: "bottom-right",
    baseWidth: 820,
    baseHeight: 520,
    minWidth: 560,
    minHeight: 320,
    maxWidth: 1400,
    maxHeight: 900
  });
  useEffect(() => inputRef.current?.focus(), []);
  useEffect(() => {
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    globalThis.addEventListener("keydown", escape);
    return () => globalThis.removeEventListener("keydown", escape);
  }, [onClose]);
  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return commands;
    return commands.filter((command) =>
      `${command.label} ${command.detail} ${command.keywords}`
        .toLowerCase()
        .includes(normalized)
    );
  }, [commands, query]);

  return (
    <div className="command-layer">
      <button className="modal-backdrop" type="button" onClick={onClose}>
        <span className="sr-only">Close command palette</span>
      </button>
      <section
        ref={resize.panelRef}
        style={resize.panelStyle}
        className={`command-palette glass-panel ${resize.panelClassName}`}
        role="dialog"
        aria-modal="true"
      >
        <div className="command-input">
          <Icon name="search" />
          <input
            ref={inputRef}
            placeholder="Search commands, nodes, providers…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && results[0]) {
                results[0].run();
                onClose();
              }
            }}
          />
          <kbd>ESC</kbd>
        </div>
        <div className="command-results">
          <span className="command-group-label">COMMANDS</span>
          {results.map((command) => (
            <button
              type="button"
              key={command.id}
              onClick={() => {
                command.run();
                onClose();
              }}
            >
              <span className="command-glyph">
                <Icon name="command" />
              </span>
              <span>
                <strong>{command.label}</strong>
                <small>{command.detail}</small>
              </span>
              <kbd>↵</kbd>
            </button>
          ))}
          {!results.length ? <p className="no-results">No matching commands.</p> : null}
        </div>
        {resize.handle}
      </section>
    </div>
  );
}
