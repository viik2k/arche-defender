# The window: score, a tree of check families, and the findings for whatever is selected.
# Scans run on a worker thread; the Tk thread only drains a queue, so slow checks never freeze the UI.
import queue, threading
from concurrent.futures import ThreadPoolExecutor
from . import core
from .core import CHECKS, ACTIONS, INFO, WARN, ALERT, run_check, load_baseline, save_baseline, load_ignored, set_ignored
from .cli import pick

BG, PANEL, FG, MUTED, LINE = '#14161a', '#1b1e23', '#e8eaed', '#9aa0a6', '#2a2e35'
RED, ORANGE, AMBER, GREEN = '#ff6b6b', '#ff9f5a', '#f5c451', '#7bd88f'
MARK = {ALERT: '[!] ', WARN: '[-] '}


def gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    root = tk.Tk(className='arche-defender')
    root.title('Arche Defender'); root.geometry('1180x720'); root.configure(bg=BG)
    st = ttk.Style(root); st.theme_use('clam')
    st.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=FG, borderwidth=0, rowheight=26)
    st.map('Treeview', background=[('selected', LINE)], foreground=[('selected', FG)])
    st.layout('Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])

    top = tk.Frame(root, bg=BG); top.pack(fill='x', padx=14, pady=(14, 10))
    tk.Label(top, text='ARCHE DEFENDER', bg=BG, fg=FG, font=('TkDefaultFont', 16, 'bold')).pack(side='left')
    score = tk.Label(top, text='', bg=BG, fg=MUTED, font=('TkDefaultFont', 14, 'bold')); score.pack(side='left', padx=18)
    flat = dict(relief='flat', bd=0, padx=16, pady=6, highlightthickness=0, cursor='hand2')
    btn = lambda txt, bg='#2a2e35', **k: tk.Button(top, text=txt, bg=bg, fg='white' if bg != '#2a2e35' else FG,
                                                   activebackground='#3a3f47', activeforeground=FG, **flat, **k)
    full = btn('Full scan', bg='#2f6f4f', font=('TkDefaultFont', 10, 'bold')); full.pack(side='right')
    quick = btn('Quick scan', bg='#2f6f4f', font=('TkDefaultFont', 10, 'bold')); quick.pack(side='right', padx=8)
    save = btn('Accept as baseline'); save.pack(side='right')
    report = btn('Save report'); report.pack(side='right', padx=8)
    tools = tk.Menubutton(top, text='Tools', bg='#2a2e35', fg=FG, activebackground='#3a3f47', activeforeground=FG,
                          relief='flat', bd=0, padx=16, pady=6, highlightthickness=0, cursor='hand2')
    tools.pack(side='right'); menu = tk.Menu(tools, tearoff=0, bg=PANEL, fg=FG); tools['menu'] = menu

    status = tk.Label(root, bg=BG, fg=MUTED, anchor='w'); status.pack(side='bottom', fill='x', padx=14, pady=(0, 10))
    body = tk.Frame(root, bg=BG); body.pack(fill='both', expand=True, padx=14)
    tree = ttk.Treeview(body, show='tree', selectmode='browse'); tree.column('#0', width=330, stretch=False)
    tree.pack(side='left', fill='y', padx=(0, 10))
    for tag, c in (('alert', RED), ('warn', ORANGE), ('new', AMBER), ('ok', GREEN), ('idle', MUTED)): tree.tag_configure(tag, foreground=c)
    tree.tag_configure('family', font=('TkDefaultFont', 10, 'bold'))
    det = tk.Text(body, bg=PANEL, fg='#cfd3d8', bd=0, highlightthickness=0, wrap='word', font=('monospace', 10), padx=10, pady=10)
    bar = tk.Scrollbar(body, command=det.yview, bg=PANEL, troughcolor=BG, bd=0, highlightthickness=0, elementborderwidth=0)
    det.config(yscrollcommand=bar.set); bar.pack(side='right', fill='y'); det.pack(side='left', fill='both', expand=True)
    for tag, c in (('alert', RED), ('warn', ORANGE), ('new', AMBER), ('fix', MUTED), ('head', FG)): det.tag_configure(tag, foreground=c)
    det.tag_configure('head', font=('TkDefaultFont', 11, 'bold'), spacing1=8, spacing3=4)

    results, q, busy, refs = {}, queue.Queue(), [], {}   # refs: text tag -> (check, row text, is ignored, fix) for right-click
    hist, mon = list(core.jsonf(core.HISTORY) or []), {}   # busy holds the running scan's kind ('quick', 'full', or None for a partial re-scan)
    tree.insert('', 'end', 'overview', text='  Overview', tags=('family',))
    for n, c in CHECKS.items():
        if not tree.exists('f:' + c.family): tree.insert('', 'end', 'f:' + c.family, text='  ' + c.family, open=True, tags=('family',))
        tree.insert('f:' + c.family, 'end', 'c:' + n, text=n + ('  (full scan)' if c.slow else ''), tags=('idle',))

    def rows_line(r):
        return MARK.get(r.sev, '[+] ' if r.new else '    ') + r.text + '\n', 'alert' if r.sev == ALERT else 'warn' if r.sev else 'new' if r.new else ''

    def ref(n, t, ignored=False, fix=None):
        refs[f'r{len(refs)}'] = (n, t, ignored, fix)
        return f'r{len(refs) - 1}'

    def write_rows(n, rows):
        for r in rows:
            line, tag = rows_line(r)
            k = ref(n, r.text, fix=r.fix)
            det.insert('end', line, (tag, k) if tag else k)
            if r.fix and (r.sev or r.new): det.insert('end', f'      fix: {r.fix}\n', ('fix', k))

    def show(_=None):
        sel = (tree.selection() or ('overview',))[0]
        det.config(state='normal'); det.delete('1.0', 'end'); refs.clear()
        if sel.startswith('c:'):
            n = sel[2:]
            if n not in results: det.insert('end', 'Not scanned yet.' + ('  This check runs in a full scan.' if CHECKS[n].slow else ''))
            elif not results[n]: det.insert('end', 'Nothing to report.')
            else: write_rows(n, results[n])
            for t in sorted(load_ignored().get(n, ())): det.insert('end', f'    ignored: {t}\n', ('fix', ref(n, t, True)))
        else:
            fam = None if sel == 'overview' else sel[2:]
            if sel == 'overview' and hist:
                h = hist[-30:]; d = h[-1]['score'] - h[-2]['score'] if len(h) > 1 else 0
                det.insert('end', f"Score {h[-1]['score']}/100" + (f' ({d:+} since the scan before)' if d else '') + f'   history: {core.spark(h)}\n', 'head')
                det.insert('end', ('Background monitor on: hourly scans and a watch on Downloads and autostart.' if monitor_on() else
                                   'Background monitor off: Tools > install-monitor scans hourly and watches your Downloads.') + '\n\n', 'fix')
            names = [n for n, c in CHECKS.items() if n in results and fam in (None, c.family)]
            hits = [(n, [r for r in results[n] if r.sev or r.new]) for n in names]
            if not names: det.insert('end', 'Run a scan to see findings.')
            elif not any(h for _, h in hits): det.insert('end', 'Nothing flagged. ' + ('Everything matches your baseline.' if load_baseline() else ''))
            for n, h in sorted(hits, key=lambda x: -max([r.sev for r in x[1]] or [0])):
                if h: det.insert('end', n + '\n', 'head'); write_rows(n, h)
        det.config(state='disabled')

    def monitor_on():   # one systemctl call per window (and per Tools action), not one per repaint
        if 'on' not in mon: mon['on'] = core.sh('systemctl', '--user', 'is-active', 'arche-defender.timer').strip() == 'active'
        return mon['on']

    def paint(n):
        rows = results[n]
        a, w, nw = (sum(r.sev == ALERT for r in rows), sum(r.sev == WARN for r in rows), sum(r.new for r in rows))
        label = f'{n}  ({a} alert)' if a else f'{n}  ({w} to fix)' if w else f'{n}  ({nw} new)' if nw else f'{n}  ({len(rows)})'
        tree.item('c:' + n, text=label, tags=('alert' if a else 'warn' if w else 'new' if nw else 'ok',))

    def headline():
        s = core.score(results)
        score.config(text=f'{s}/100', fg=GREEN if s >= 90 else AMBER if s >= 70 else RED)

    def worker(names, base):
        with ThreadPoolExecutor(6) as ex:
            for n, rows in zip(names, ex.map(lambda n: run_check(n, base), names)): q.put((n, rows))
        q.put(None)

    def drain():
        try:
            while True:
                m = q.get_nowait()
                if m is None: return finish()
                results[m[0]] = m[1]; paint(m[0]); headline()
                status.config(text=f'Scanning ... {m[0]} done')
                if tree.selection() and tree.selection()[0] in ('c:' + m[0], 'overview'): show()
        except queue.Empty: root.after(100, drain)

    def start(full_scan, names=None):
        if busy: return
        busy.append(None if names else 'full' if full_scan else 'quick'); quick.config(state='disabled'); full.config(state='disabled')
        names = names or pick(full_scan)
        for n in names: results.pop(n, None); tree.item('c:' + n, text=n + '  ...', tags=('idle',))
        status.config(text='Scanning ...')
        threading.Thread(target=worker, args=(names, load_baseline()), daemon=True).start()
        root.after(100, drain)

    def finish():
        if busy[0]: hist[:] = core.record(results, busy[0])
        busy.clear(); quick.config(state='normal'); full.config(state='normal')
        rows = [r for rs in results.values() for r in rs]
        base = load_baseline()
        status.config(text=core.stamp() + f'  {sum(r.sev == ALERT for r in rows)} alerts, {sum(r.sev == WARN for r in rows)} to fix, '
                      f'{sum(r.new for r in rows)} new since baseline.'
                      + ('' if base is not None else '  No baseline yet: review the lists, then Accept as baseline.'))
        show()

    def do_save():
        if busy or not results: return
        save_baseline(results); start(False)

    def do_report():
        if not results: return
        p = filedialog.asksaveasfilename(defaultextension='.html', initialfile='arche-defender-report.html',
                                         filetypes=[('HTML report', '*.html'), ('JSON', '*.json')])
        if not p: return
        from . import report
        report.write(p, results, load_baseline())
        status.config(text=f'Report saved: {p}')

    def run_action(name):
        fn, helptext, argname = ACTIONS[name]
        arg = None
        if argname:
            arg = (filedialog.askopenfilename(title=helptext) if 'path' in argname.lower() else simpledialog.askstring(name, helptext))
            if not arg: return
        status.config(text=f'Running {name} ...')

        def go():
            try: msg = fn(arg) if argname else fn()
            except Exception as e: msg = f'{name} failed: {e}'
            mon.clear()
            root.after(0, lambda: (status.config(text=str(msg).splitlines()[0] if msg else name + ' done'),
                                   messagebox.showinfo(name, str(msg))))
        threading.Thread(target=go, daemon=True).start()

    for n, (_, h, _) in ACTIONS.items(): menu.add_command(label=f'{n}: {h}', command=lambda n=n: run_action(n))
    if not ACTIONS: menu.add_command(label='No tools installed', state='disabled')

    def context(e):
        hit = next((refs[t] for t in det.tag_names(f'@{e.x},{e.y}') if t in refs), None)
        if not hit: return
        n, t, ignored, fix = hit
        m = tk.Menu(det, tearoff=0, bg=PANEL, fg=FG)
        if ignored: m.add_command(label='Show this finding again', command=lambda: (set_ignored(n, t, False), start(False, [n])))
        else: m.add_command(label='Ignore this finding', command=lambda: (set_ignored(n, t), results.__setitem__(
            n, [r for r in results[n] if r.text != t]), paint(n), headline(), show()))
        m.add_command(label='Copy', command=lambda: (root.clipboard_clear(), root.clipboard_append(f'{n}: {t}')))
        if fix: m.add_command(label='Copy the fix', command=lambda: (root.clipboard_clear(), root.clipboard_append(fix)))
        m.tk_popup(e.x_root, e.y_root)

    det.bind('<Button-3>', context)
    tree.bind('<<TreeviewSelect>>', show)
    quick.config(command=lambda: start(False)); full.config(command=lambda: start(True))
    save.config(command=do_save); report.config(command=do_report)
    tree.selection_set('overview')
    root.after(100, lambda: start(False))
    root.mainloop()
