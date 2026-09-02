// Inline SVG icons — no icon dependency. All inherit `currentColor`.

const base = {
  xmlns: 'http://www.w3.org/2000/svg',
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': 'true',
  focusable: 'false',
}

export function ShieldCheck({ size = 24, strokeWidth = 2 }) {
  return (
    <svg {...base} width={size} height={size} strokeWidth={strokeWidth}>
      <path d="M12 3l7 3v5.5c0 4.3-2.9 7.9-7 9.5-4.1-1.6-7-5.2-7-9.5V6l7-3z" />
      <path d="M9 12.2l2.1 2.1L15.2 10" />
    </svg>
  )
}

export function ShieldAlert({ size = 24 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M12 3l7 3v5.5c0 4.3-2.9 7.9-7 9.5-4.1-1.6-7-5.2-7-9.5V6l7-3z" />
      <path d="M12 9v4" />
      <path d="M12 16.5h.01" />
    </svg>
  )
}

export function Lock({ size = 16 }) {
  return (
    <svg {...base} width={size} height={size}>
      <rect x="4" y="10" width="16" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
  )
}

export function Check({ size = 20 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M4.5 12.5l5 5 10-11" />
    </svg>
  )
}

export function Flag({ size = 18 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M5 21V4" />
      <path d="M5 4.5h11l-2 3.5 2 3.5H5z" />
    </svg>
  )
}

export function ChevronDown({ size = 18 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M6 9.5l6 6 6-6" />
    </svg>
  )
}

export function UserIcon({ size = 20 }) {
  return (
    <svg {...base} width={size} height={size}>
      <circle cx="12" cy="8" r="3.5" />
      <path d="M4.5 20a7.5 7.5 0 0 1 15 0" />
    </svg>
  )
}

export function LinkIcon({ size = 20 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M10 13.5a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1.4 1.4" />
      <path d="M14 10.5a4 4 0 0 0-5.7 0l-3 3a4 4 0 1 0 5.7 5.7l1.4-1.4" />
    </svg>
  )
}

export function ClipIcon({ size = 20 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M20 11.5l-7.8 7.8a4.5 4.5 0 1 1-6.4-6.4l8-8a3 3 0 1 1 4.3 4.3l-8 8a1.5 1.5 0 1 1-2.1-2.1l7.1-7.1" />
    </svg>
  )
}

export function MessageIcon({ size = 20 }) {
  return (
    <svg {...base} width={size} height={size}>
      <path d="M20 15a2 2 0 0 1-2 2H8l-4 3V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2z" />
    </svg>
  )
}

const CATEGORY_ICONS = {
  auth: ShieldAlert,
  identity: UserIcon,
  links: LinkIcon,
  attach: ClipIcon,
  content: MessageIcon,
}

export function CategoryIcon({ category, size = 20 }) {
  const Cmp = CATEGORY_ICONS[category] || ShieldAlert
  return <Cmp size={size} />
}
