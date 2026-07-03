project('consensus-diff', meson_version: '>=1.2')

uv = find_program('uv')

test('unit', uv,
  args: ['run', 'pytest', 'tests', '-q'],
  suite: 'unit', timeout: 300, workdir: meson.project_source_root())

run_target('diff-smoke',
  command: [uv, 'run', 'pytest', 'test_diff.py', '-q', '--fork=gloas', '--preset=minimal'])
run_target('diff-full-minimal',
  command: [uv, 'run', 'pytest', 'test_diff.py', '--fork=gloas', '--preset=minimal', '--subset=0', '-n', 'auto', '-q'])
run_target('diff-full-mainnet',
  command: [uv, 'run', 'pytest', 'test_diff.py', '--fork=gloas', '--preset=mainnet', '--subset=0', '-n', '4', '-q'])
