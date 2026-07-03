project('consensus-diff', meson_version: '>=1.2')

uv = find_program('uv')
src = meson.project_source_root()

test('unit', uv,
  args: ['run', 'pytest', 'tests', '-q'],
  suite: 'unit', timeout: 300, workdir: src)

diff_args = ['run', 'pytest', src / 'test_diff.py',
  '--backends=' + (src / 'backends.toml'),
  '--report-dir=' + (src / 'reports')]

run_target('diff-smoke',
  command: [uv] + diff_args + ['-q', '--fork=gloas', '--preset=minimal'])
# Serial for now (-n 1): concurrent backend spawns across xdist workers load the
# box enough to flake the handshake-grace check; single-worker sidesteps it (and
# makes the archive-cache flock belt-and-suspenders). Revisit once the handshake
# is made load-robust.
run_target('diff-full-minimal',
  command: [uv] + diff_args + ['--fork=gloas', '--preset=minimal', '--subset=0', '-n', '1', '-q'])
run_target('diff-full-mainnet',
  command: [uv] + diff_args + ['--fork=gloas', '--preset=mainnet', '--subset=0', '-n', '1', '-q'])
