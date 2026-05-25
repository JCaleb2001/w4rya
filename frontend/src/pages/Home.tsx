const shortcutTableData = [
  [
    { key: 'j/k', action: 'Down/Up in FlowList' },
    { key: 'h/l', action: 'Up/Down in Flow' },
    { key: 's', action: 'Focus (s)earch bar' },
    { key: 'esc', action: 'Unfocus search bar' },
  ],
  [
    { key: 'a', action: 'L(a)st 5 ticks' },
    { key: 'c', action: '(C)lear time selection' },
    { key: 'r', action: '(R)efresh flows' },
  ],
  [
    { key: 'd', action: '(D)iff view' },
    { key: 'f', action: 'Load flow to (f)irst diff slot' },
    { key: 'e', action: 'Load flow to s(e)cond diff slot' },
    { key: 'g', action: '(G)raph view' },
  ],
  [
    { key: 'w', action: 'Scroll to current flo(w) in flow list' },
    { key: 'i/o', action: 'Toggle flag in/out filters' },
    { key: 't', action: 'Toggle s(t)arred filters' },
    { key: 'x', action: 'Star selected flow' },
  ]
];

const generateShortcutTable = (data: { key: string; action: string; }[][]) => {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 w-full max-w-6xl">
      {data.map((table, tableIndex) => (
        <div
          key={tableIndex}
          className="bg-hax-surface border border-hax-border rounded-sm overflow-hidden"
          style={{ boxShadow: '0 0 24px -16px rgba(168, 85, 247, 0.45)' }}
        >
          <div className="bg-hax-elev px-3 py-1 border-b border-hax-border text-[10px] uppercase tracking-[0.2em] text-hax-accent-bright font-mono">
            ▎block {String(tableIndex + 1).padStart(2, '0')}
          </div>
          <table className="w-full text-xs font-mono">
            <tbody>
              {table.map((row, rowIndex) => (
                <tr key={rowIndex} className="border-t border-hax-border first:border-t-0">
                  <td className="px-3 py-1.5 text-hax-accent-bright w-1/3 align-top whitespace-nowrap">
                    <span className="bg-hax-elev px-2 py-0.5 rounded-sm border border-hax-border">
                      {row.key}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-hax-muted">
                    {row.action}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
};


export function Home() {
  return (
    <div className="p-8 flex flex-col gap-8 items-center min-h-full bg-hax-bg text-hax-text font-mono">
      <div className="flex items-center gap-6 mt-6">
        <img
          src="/logo.png"
          alt="w4rya"
          className="h-28 w-28"
          style={{ filter: 'drop-shadow(0 0 18px rgba(168, 85, 247, 0.65))' }}
        />
        <div>
          <h1
            className="text-7xl font-bold tracking-[0.18em] text-hax-text"
            style={{ textShadow: '0 0 18px rgba(168, 85, 247, 0.6)' }}
          >
            W4RYA
          </h1>
          <h2 className="text-sm uppercase tracking-[0.4em] text-hax-accent-bright mt-1">
            &gt; flow analyzer
          </h2>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 text-[11px] uppercase tracking-[0.2em]">
        <span className="px-3 py-1 border border-hax-success/40 text-hax-success bg-hax-success/5 rounded-sm">
          ● system online
        </span>
        <span className="px-3 py-1 border border-hax-accent/40 text-hax-accent-bright bg-hax-accent/5 rounded-sm">
          ● ingest active
        </span>
        <span className="px-3 py-1 border border-hax-border text-hax-muted bg-hax-surface rounded-sm">
          ctf mode
        </span>
        <span className="px-3 py-1 border border-hax-border text-hax-muted bg-hax-surface rounded-sm">
          no-ai runtime
        </span>
      </div>

      <div className="text-hax-muted text-sm">
        <span className="text-hax-accent-bright">~</span>
        <span className="text-hax-text">$</span>
        <span className="ml-2">awaiting target<span className="hax-cursor"></span></span>
      </div>

      <div className="w-full flex flex-col items-center gap-3">
        <div className="text-xs uppercase tracking-[0.35em] text-hax-muted">
          [ keymap reference ]
        </div>
        {generateShortcutTable(shortcutTableData)}
      </div>

      <div className="text-[10px] uppercase tracking-[0.3em] text-hax-dim mt-auto pt-6">
        v0.3.0 // hard fork of tulip · gpl-3.0
      </div>
    </div>
  );
}
