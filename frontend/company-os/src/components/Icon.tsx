import type { SVGProps } from "react";

type IconName =
  | "command"
  | "search"
  | "history"
  | "settings"
  | "layers"
  | "focus"
  | "reset"
  | "close"
  | "copy"
  | "alert"
  | "spark"
  | "sun"
  | "moon";

export function Icon({
  name,
  ...props
}: SVGProps<SVGSVGElement> & { name: IconName }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const
  };
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" {...props}>
      {name === "command" ? (
        <>
          <path {...common} d="M9 6V5a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v14a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V5" />
        </>
      ) : null}
      {name === "search" ? (
        <>
          <circle {...common} cx="10.5" cy="10.5" r="6.5" />
          <path {...common} d="m15.5 15.5 4 4" />
        </>
      ) : null}
      {name === "history" ? (
        <>
          <path {...common} d="M4 7v5h5" />
          <path {...common} d="M5.4 16.8A8 8 0 1 0 4 12" />
          <path {...common} d="M12 7.5V12l3 2" />
        </>
      ) : null}
      {name === "settings" ? (
        <>
          <circle {...common} cx="12" cy="12" r="3" />
          <path {...common} d="M19 13.5v-3l-2-.7-.7-1.7.9-1.9-2.1-2.1-1.9.9-1.7-.7-.7-2h-3l-.7 2-1.7.7-1.9-.9-2.1 2.1.9 1.9-.7 1.7-2 .7v3l2 .7.7 1.7-.9 1.9 2.1 2.1 1.9-.9 1.7.7.7 2h3l.7-2 1.7-.7 1.9.9 2.1-2.1-.9-1.9.7-1.7z" />
        </>
      ) : null}
      {name === "layers" ? (
        <>
          <path {...common} d="m12 3 9 5-9 5-9-5z" />
          <path {...common} d="m3 12 9 5 9-5M3 16l9 5 9-5" />
        </>
      ) : null}
      {name === "focus" ? (
        <>
          <path {...common} d="M8 3H3v5M16 3h5v5M8 21H3v-5M16 21h5v-5" />
          <circle {...common} cx="12" cy="12" r="3" />
        </>
      ) : null}
      {name === "reset" ? (
        <>
          <path {...common} d="M4 7v5h5" />
          <path {...common} d="M5.6 16.8A8 8 0 1 0 4 12" />
          <path {...common} d="M9 12h6M12 9v6" />
        </>
      ) : null}
      {name === "close" ? <path {...common} d="m5 5 14 14M19 5 5 19" /> : null}
      {name === "copy" ? (
        <>
          <rect {...common} x="8" y="8" width="11" height="11" rx="2" />
          <path {...common} d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
        </>
      ) : null}
      {name === "alert" ? (
        <>
          <path {...common} d="M10.3 4.2 2.5 18a2 2 0 0 0 1.7 3h15.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z" />
          <path {...common} d="M12 9v4M12 17h.01" />
        </>
      ) : null}
      {name === "spark" ? (
        <>
          <path {...common} d="m12 2 1.4 5.1L18 10l-4.6 2.9L12 18l-1.4-5.1L6 10l4.6-2.9z" />
          <path {...common} d="m19 16 .7 2.3L22 19l-2.3.7L19 22l-.7-2.3L16 19l2.3-.7z" />
        </>
      ) : null}
      {name === "sun" ? (
        <>
          <circle {...common} cx="12" cy="12" r="4" />
          <path {...common} d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </>
      ) : null}
      {name === "moon" ? (
        <path {...common} d="M20.4 15.2A8.5 8.5 0 0 1 8.8 3.6 8.5 8.5 0 1 0 20.4 15.2z" />
      ) : null}
    </svg>
  );
}
