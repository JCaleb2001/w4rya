import classNames from "classnames";
import Color from "color";

// Dark-friendly hashed color: low lightness so it doesn't blow out on dark bg
const computeColorFromString = (str: string) => {
  const hue = Array.from(str).reduce(
    (hash, char) => 0 | (31 * hash + char.charCodeAt(0)),
    0
  );
  return Color(`hsl(${Math.abs(hue) % 360}, 60%, 38%)`).hex();
};

// Hardcoded colors for known tags — dark / saturated so they pop on the hax bg
const tagColorMap: Record<string, string> = {
  fishy: "#1e3a8a",       // deep blue
  blocked: "#7e22ce",     // purple-700 (matches accent palette)
  flag_out: "#7f1d1d",    // dark red
  flag_in: "#14532d",     // dark green
  "flag-out": "#7f1d1d",
  "flag-in": "#14532d",
  enemy: "#991b1b",
  suricata: "#9333ea",
  starred: "#b45309",
};

export function tagToColor(tag: string) {
  return tagColorMap[tag] ?? computeColorFromString(tag);
}

interface TagProps {
  tag: string;
  color?: string;
  disabled?: boolean;
  excluded?: boolean;
  onClick?: () => void;
}
export const Tag = ({ tag, color, disabled = false, excluded = false, onClick }: TagProps) => {
  const bg = color ?? tagToColor(tag);

  let tagBackgroundColor: string;
  let tagTextColor: string;
  let border = '1px solid transparent';

  if (excluded) {
    tagBackgroundColor = '#0a0a0f';
    tagTextColor = '#ef4444';
    border = '1px solid #7f1d1d';
  } else if (disabled) {
    tagBackgroundColor = '#1c1c28';
    tagTextColor = '#5a5a72';
    border = '1px solid #2a2a3a';
  } else {
    tagBackgroundColor = bg;
    tagTextColor = Color(bg).isDark() ? '#e4e4ed' : '#0a0a0f';
    border = `1px solid ${Color(bg).lighten(0.3).hex()}`;
  }

  return (
    <div
      onClick={onClick}
      className={classNames(
        "px-2 py-0.5 cursor-pointer rounded-sm uppercase text-[10px] tracking-wider h-5 text-center flex items-center hover:opacity-90 transition-all duration-150 text-ellipsis overflow-hidden whitespace-nowrap font-mono"
      )}
      style={{
        backgroundColor: tagBackgroundColor,
        color: tagTextColor,
        border,
        letterSpacing: '0.08em',
      }}
    >
      <span style={excluded ? { textDecoration: 'line-through' } : {}}>{tag}</span>
    </div>
  );
};
