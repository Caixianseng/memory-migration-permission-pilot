"""Run the frozen persistent-exchange tests with live inference disabled.

Only the standard-library receiver SQLite reader may start a real child
process. Native model clients, gateway calls and outbound sockets are blocked.
Individual tests may replace these guards with their own explicit mocks.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def blocked(*args, **kwargs):
    raise RuntimeError('offline_suite_forbids_live_model_or_network_execution')


def main() -> int:
    from experiments.persistent_exchange_v1 import model_runtime

    real_run = subprocess.run
    reader = (ROOT / 'experiments/persistent_exchange_v1/read_receiver.py').resolve()

    def reader_only(argv, *args, **kwargs):
        if not isinstance(argv, (list, tuple)) or len(argv) < 3:
            return blocked()
        if Path(argv[0]).resolve() != Path(sys.executable).resolve():
            return blocked()
        prefixes = (['-B'], ['-B', '-X', 'utf8'])
        if not any(list(argv[1:1 + len(flags)]) == flags
                   and len(argv) > 1 + len(flags)
                   and Path(argv[1 + len(flags)]).resolve() == reader
                   for flags in prefixes):
            return blocked()
        if kwargs.get('shell'):
            return blocked()
        return real_run(argv, *args, **kwargs)

    modules = [f'experiments.persistent_exchange_v1.{p.stem}'
               for p in sorted((ROOT / 'experiments/persistent_exchange_v1').glob('test_*.py'))]
    modules.append('scripts.test_persistent_exchange_public_portability')
    previous_tempdir = tempfile.tempdir
    try:
        # Canonicalise fixture storage only; production path checks stay intact.
        with tempfile.TemporaryDirectory(prefix='persistent-offline-',
                dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            tempfile.tempdir = str(Path(temporary).resolve())
            with ExitStack() as stack:
                stack.enter_context(patch.object(model_runtime, 'PYTHON', sys.executable))
                from experiments.persistent_exchange_v1 import receiver_runtime
                from experiments.persistent_exchange_v1 import receiver_paid_runtime
                from experiments.persistent_exchange_v1 import receiver_recovery

                # These tests hash a driver as fixture data, never execute it.
                # Use an explicitly synthetic file instead of requiring the
                # separately obtained, machine-local native gateway package.
                mock_driver = Path(temporary) / 'MOCK-offline-native-driver.mjs'
                mock_driver.write_text('// MOCK ONLY: never executed\n', encoding='utf-8')
                stack.enter_context(patch.object(receiver_runtime, 'PYTHON', sys.executable))
                stack.enter_context(patch.object(receiver_paid_runtime, 'PYTHON', sys.executable))
                stack.enter_context(patch.object(receiver_paid_runtime, 'DRIVER', mock_driver))
                stack.enter_context(patch.object(receiver_recovery, 'DRIVER', mock_driver))
                stack.enter_context(patch.object(model_runtime, 'generate_memory', blocked))
                stack.enter_context(patch.object(model_runtime, 'run_workbuddy', blocked))
                stack.enter_context(patch.object(model_runtime, 'call_gateway', blocked))
                stack.enter_context(patch.object(model_runtime.FlashSDKClient, '__init__', blocked))
                stack.enter_context(patch.object(subprocess, 'run', reader_only))
                stack.enter_context(patch.object(socket, 'create_connection', blocked))
                stack.enter_context(patch.object(socket.socket, 'connect', blocked))
                if os.name != 'nt':
                    # The frozen method mixes generic terminal-cost checks
                    # with a real Windows drive-namespace fixture. A POSIX
                    # pathname prefixed with \\?\ is not that Windows alias.
                    # Do not relax the production path resolver to emulate it.
                    # The portable companion below retains the generic checks
                    # and also verifies that POSIX does not accept this alias.
                    from experiments.persistent_exchange_v1 import test_finalize
                    case = test_finalize.PersistentExchangeFinalAuditTests
                    method = 'test_terminal_queue_submission_has_unknown_execution_and_namespace_is_same_path'
                    stack.enter_context(patch.object(case, method, unittest.skip(
                        'Windows drive-namespace fixture; generic checks run in the portable companion'
                    )(getattr(case, method))))
                loaded = unittest.defaultTestLoader.loadTestsFromNames(modules)
                # Some mock fixtures import a TestCase from another module.
                # Execute each test ID once instead of recounting that import.
                seen = set()
                suite = unittest.TestSuite()

                def include(items):
                    for item in items:
                        if isinstance(item, unittest.TestSuite):
                            include(item)
                        elif item.id() not in seen:
                            seen.add(item.id())
                            suite.addTest(item)

                include(loaded)
                result = unittest.TextTestRunner(verbosity=2).run(suite)
                return 0 if result.wasSuccessful() else 1
    finally:
        tempfile.tempdir = previous_tempdir


if __name__ == '__main__':
    raise SystemExit(main())
