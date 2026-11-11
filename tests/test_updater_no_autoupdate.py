"""The startup check may announce an update, never apply one."""

from types import SimpleNamespace
from unittest.mock import patch

from wifite.util.updater import Updater


def _result(stdout='', returncode=0, stderr=''):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


class FakeGit:
    """Answers the git commands _run() issues, in call order-independent form."""

    def __init__(self, local='aaa1111', remote='bbb2222', fetch_rc=0,
                 ancestor_rc=0, count='3'):
        self.local = local
        self.remote = remote
        self.fetch_rc = fetch_rc
        self.ancestor_rc = ancestor_rc
        self.count = count
        self.calls = []

    def __call__(self, root, *args, **kwargs):
        self.calls.append(args)
        joined = ' '.join(args)
        if joined == 'rev-parse --abbrev-ref HEAD':
            return _result('master\n')
        if 'symbolic-full-name' in joined:
            return _result('origin/master\n')
        if args[0] == 'fetch':
            return _result('', self.fetch_rc, 'network down')
        if joined == 'rev-parse HEAD':
            return _result(self.local + '\n')
        if joined.startswith('rev-parse origin/master'):
            return _result(self.remote + '\n')
        if args[0] == 'merge-base':
            return _result('', self.ancestor_rc)
        if args[0] == 'rev-list':
            return _result(self.count + '\n')
        if args[0] == 'log':
            return _result('bbb2222 fix: something\n')
        if args[0] == 'status':
            return _result('')
        if args[0] == 'merge':
            return _result('', 0)
        return _result('')


def _run(git, apply, verbose=0):
    with patch.object(Updater, '_repo_root', return_value='/repo'), \
         patch.object(Updater, '_git_available', return_value=True), \
         patch.object(Updater, '_git', side_effect=git), \
         patch.object(Updater, '_reexec') as reexec, \
         patch('wifite.util.updater.Color.pl') as pl:
        result = Updater.check_and_update(verbose=verbose, apply=apply)

    text = ' '.join(str(call.args[0]) for call in pl.call_args_list)
    return result, text, git, reexec


def test_startup_check_announces_without_fast_forwarding():
    git = FakeGit()

    result, text, git, reexec = _run(git, apply=False)

    assert result == 'available'
    assert 'UPDATE AVAILABLE' in text
    assert '--update' in text
    assert not any(call[0] == 'merge' for call in git.calls)
    reexec.assert_not_called()


def test_startup_check_is_quiet_when_current():
    git = FakeGit(local='same', remote='same')

    result, text, git, reexec = _run(git, apply=False)

    assert result == 'current'
    assert 'Checking for updates' not in text
    reexec.assert_not_called()


def test_explicit_update_still_applies():
    git = FakeGit()

    result, text, git, reexec = _run(git, apply=True)

    assert result == 'updated'
    assert 'Checking for updates' in text
    assert any(call[0] == 'merge' for call in git.calls)
    reexec.assert_called_once()


def test_fetch_failure_still_skips():
    result, text, git, reexec = _run(FakeGit(fetch_rc=1), apply=False)

    assert result == 'skipped'
    reexec.assert_not_called()