#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Self-update support for wifite2.

On startup wifite checks its own git checkout against the GitHub remote and
reports when the remote has new commits. It does not apply them: only the
explicit ``--update`` command fast-forwards the checkout and re-executes the
process so the freshly pulled code runs immediately.

The check is intentionally conservative:
  * It only runs inside a git checkout (not for pip/package installs).
  * Check-only mode never touches the working tree; a dirty tree or a
    diverged branch is reported and skipped in apply mode.
  * All git calls use short timeouts so a slow or offline network cannot hang
    startup.
"""

import os
import subprocess
import sys

from .color import Color


class Updater(object):
    """Checks GitHub for a newer commit; only --update fast-forwards the checkout."""

    # Guards against an endless re-exec loop: set before re-launching wifite.
    REEXEC_ENV_FLAG = 'WIFITE_UPDATED'

    # Timeouts (seconds) for individual git operations.
    FETCH_TIMEOUT = 15
    GIT_TIMEOUT = 10

    @staticmethod
    def _repo_root():
        """
        Return the git checkout root (the parent of the ``wifite`` package),
        or None if wifite is not running from a git checkout.
        """
        # .../wifite2/wifite/util/updater.py -> .../wifite2
        package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        root = os.path.dirname(package_dir)
        if os.path.isdir(os.path.join(root, '.git')):
            return root
        return None

    @staticmethod
    def _git(root, *args, **kwargs):
        """Run a git command in ``root`` and return a CompletedProcess."""
        timeout = kwargs.pop('timeout', Updater.GIT_TIMEOUT)
        return subprocess.run(
            ['git', '-C', root] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
        )

    @staticmethod
    def _git_available():
        """Return True if the git binary is callable."""
        try:
            subprocess.run(
                ['git', '--version'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=Updater.GIT_TIMEOUT,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    @classmethod
    def check_and_update(cls, verbose=0, apply=False):
        """
        Entry point for the startup update check.

        With ``apply=False`` the checkout is only inspected: when the remote is
        ahead the user is told an update is available and how to take it. Only
        ``--update`` passes ``apply=True``, which fast-forwards and re-execs.

        Returns one of:
            'updated'   - checkout was fast-forwarded (a re-exec was attempted)
            'available' - the remote is ahead; nothing was applied
            'current'   - already on the latest commit
            'skipped'   - nothing was done (not a git checkout, offline, dirty,
                          diverged, git missing, or a previous re-exec)
        """
        # Don't re-check immediately after we re-executed following an update.
        if os.environ.get(cls.REEXEC_ENV_FLAG) == '1':
            return 'skipped'

        root = cls._repo_root()
        if root is None:
            if verbose > 0:
                Color.pl('{!} {O}Update check: not a git checkout, skipping{W}')
            return 'skipped'

        if not cls._git_available():
            if verbose > 0:
                Color.pl('{!} {O}Update check: {C}git{O} not found, skipping{W}')
            return 'skipped'

        try:
            return cls._run(root, verbose=verbose, apply=apply)
        except subprocess.TimeoutExpired:
            Color.pl('{!} {O}Update check: git timed out (offline?), skipping{W}')
            return 'skipped'
        except (OSError, subprocess.SubprocessError) as e:
            if verbose > 0:
                Color.pl('{!} {O}Update check: skipped ({W}%s{O}){W}' % str(e))
            return 'skipped'

    @classmethod
    def _run(cls, root, verbose=0, apply=False):
        # Determine the current branch. A detached HEAD has no upstream to track.
        branch_proc = cls._git(root, 'rev-parse', '--abbrev-ref', 'HEAD')
        branch = branch_proc.stdout.strip()
        if branch_proc.returncode != 0 or not branch or branch == 'HEAD':
            if verbose > 0:
                Color.pl('{!} {O}Update check: detached HEAD, skipping{W}')
            return 'skipped'

        # Resolve the upstream ref (e.g. origin/master). Fall back to origin/<branch>.
        upstream_proc = cls._git(root, 'rev-parse', '--abbrev-ref',
                                 '--symbolic-full-name', '@{u}')
        upstream = upstream_proc.stdout.strip()
        if upstream_proc.returncode != 0 or not upstream:
            upstream = 'origin/%s' % branch
        remote = upstream.split('/', 1)[0]

        if apply or verbose > 0:
            Color.pl('{+} {C}Checking for updates{W} on {G}%s{W}...' % upstream)

        # Fetch the latest refs from GitHub.
        fetch_proc = cls._git(root, 'fetch', '--quiet', remote,
                              timeout=cls.FETCH_TIMEOUT)
        if fetch_proc.returncode != 0:
            msg = (fetch_proc.stderr or fetch_proc.stdout or '').strip()
            Color.pl('{!} {O}Update check: fetch failed, skipping{W}')
            if verbose > 0 and msg:
                Color.pl('{!} {O}%s{W}' % msg)
            return 'skipped'

        local = cls._git(root, 'rev-parse', 'HEAD').stdout.strip()
        remote_head = cls._git(root, 'rev-parse', upstream).stdout.strip()

        if not remote_head:
            if verbose > 0:
                Color.pl('{!} {O}Update check: could not resolve %s, skipping{W}' % upstream)
            return 'skipped'

        if local == remote_head:
            if apply or verbose > 0:
                Color.pl('{+} {G}wifite2 is up to date{W} ({D}%s{W})' % local[:7])
            return 'current'

        # Is the remote strictly ahead (i.e. a clean fast-forward)? If HEAD is
        # not an ancestor of the remote, the branch has diverged -> don't touch it.
        ancestor = cls._git(root, 'merge-base', '--is-ancestor', 'HEAD', upstream)
        if ancestor.returncode != 0:
            Color.pl('{!} {O}Update check: local branch has diverged from {C}%s{O}; '
                     'skipping to protect local commits{W}' % upstream)
            return 'skipped'

        # Count the new commits before deciding anything.
        count = cls._git(root, 'rev-list', '--count',
                         'HEAD..%s' % upstream).stdout.strip() or '?'

        if not apply:
            # Check-only mode: say what is available and how to take it.
            Color.pl('{!} {C}UPDATE AVAILABLE{W}: use {G}--update{W} '
                     'to fast-forward ({D}%s{W} -> {C}%s{W}, %s commit(s))'
                     % (local[:7], remote_head[:7], count))
            return 'available'

        Color.pl('{+} {G}%s{W} new commit(s) available '
                 '({D}%s{W} -> {C}%s{W}):' % (count, local[:7], remote_head[:7]))

        log = cls._git(root, 'log', '--oneline', '--no-decorate',
                       '--no-color', 'HEAD..%s' % upstream).stdout.rstrip()
        for line in log.splitlines():
            Color.pl('    {D}%s{W}' % line)

        # Refuse to overwrite uncommitted changes to *tracked* files. Untracked
        # files (captures, wordlists, etc.) are ignored here: a fast-forward
        # won't touch them, and if one would collide with an incoming file the
        # merge below fails safely.
        dirty = cls._git(root, 'status', '--porcelain',
                         '--untracked-files=no').stdout.strip()
        if dirty:
            Color.pl('{!} {O}Update check: uncommitted local changes present; '
                     'not updating. Commit/stash them or run with {C}--no-update{W}')
            return 'skipped'

        # Fast-forward to the latest commit.
        Color.pl('{+} {C}Updating{W} to {C}%s{W}...' % remote_head[:7])
        merge = cls._git(root, 'merge', '--ff-only', upstream)
        if merge.returncode != 0:
            msg = (merge.stderr or merge.stdout or '').strip()
            Color.pl('{!} {R}Auto-update failed:{W} %s' % msg)
            return 'skipped'

        Color.pl('{+} {G}Updated successfully{W} to {C}%s{W}' % remote_head[:7])
        cls._reexec()
        # If re-exec fails for any reason, fall through so wifite keeps running.
        return 'updated'

    @classmethod
    def _reexec(cls):
        """Restart wifite in place so the newly pulled code takes effect."""
        Color.pl('{+} {C}Restarting wifite to apply the update...{W}')
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
        os.environ[cls.REEXEC_ENV_FLAG] = '1'
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except OSError as e:
            # Couldn't re-exec; warn and let the (old) process continue.
            Color.pl('{!} {O}Could not restart automatically (%s).{W}' % str(e))
            Color.pl('{!} {O}Please re-run wifite to use the updated version.{W}')
