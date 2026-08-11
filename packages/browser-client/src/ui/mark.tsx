export function HorizonMark({ size = 28 }: { size?: number }) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 120 120"
      fill="none"
    >
      <defs>
        <clipPath id="darknyx-horizon-mark">
          <rect width="120" height="66" />
        </clipPath>
      </defs>
      <circle
        cx="60"
        cy="60"
        r="36"
        fill="currentColor"
        clipPath="url(#darknyx-horizon-mark)"
      />
      <path d="M18 66h84v4H18z" fill="currentColor" />
      <path d="M18 78h60v4H18z" fill="currentColor" opacity=".5" />
    </svg>
  );
}
