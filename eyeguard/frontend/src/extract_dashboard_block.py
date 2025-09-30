from pathlib import Path

text = Path('pages/Dashboard.jsx').read_text()
marker = '              <p className="text-xs uppercase tracking-widest text-slate-500">Blocked IPs</p>'
idx = text.index(marker)
div_start = text.rfind('            <div className="bg', 0, idx)
div_end = text.index('            </div>', idx) + len('            </div>')
print(repr(text[div_start:div_end]))
