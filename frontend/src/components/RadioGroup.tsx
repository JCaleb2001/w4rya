import classNames from "classnames";

export interface RadioGroupProps {
  options: string[];
  value: string;
  className: string;
  onChange: (option: string) => void;
}

export function RadioGroup(props: RadioGroupProps) {
  return (
    <div className={props.className}>
      {props.options.map((option) => (
        <div
          key={option}
          onClick={() => props.onChange(option)}
          className={classNames(
            "py-1 px-3 rounded-sm cursor-pointer text-xs uppercase tracking-wider font-mono border transition-all duration-150",
            option === props.value
              ? "bg-hax-accent-deep/30 border-hax-accent text-hax-accent-bright shadow-[0_0_10px_-3px_rgba(168,85,247,0.6)]"
              : "bg-hax-elev border-hax-border text-hax-muted hover:border-hax-accent-deep hover:text-hax-text"
          )}
        >
          {option}
        </div>
      ))}
    </div>
  );
}
