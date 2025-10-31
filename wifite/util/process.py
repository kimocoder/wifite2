#!/usr/bin/env python
# -*- coding: utf-8 -*-

import contextlib
import time
import signal
import os
import atexit
import threading
import subprocess
from subprocess import Popen, PIPE
from ..util.color import Color
from ..config import Configuration


class ProcessManager:
    """Global process manager to track and cleanup all processes"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._processes = set()
                    cls._instance._registered_cleanup = False
        return cls._instance

    def register_process(self, process):
        """Register a process for cleanup tracking"""
        with self._lock:
            if len(self._processes) > 50:  # Reasonable limit
                finished = {p for p in self._processes if hasattr(p, 'is_running') and not p.is_running()}
                self._processes -= finished

                if len(self._processes) > 50:
                    oldest = list(self._processes)[:10]
                    for p in oldest:
                        try:
                            p.force_kill()
                        except Exception:
                            pass
                    self._processes -= set(oldest)

            self._processes.add(process)
            if not self._registered_cleanup:
                atexit.register(self.cleanup_all)
                self._registered_cleanup = True

    def unregister_process(self, process):
        with self._lock:
            self._processes.discard(process)

    def cleanup_all(self):
        with self._lock:
            for process in list(self._processes):
                try:
                    if process.pid and process.pid.poll() is None:
                        process.force_kill()
                except Exception:
                    pass
            self._processes.clear()


class Process(object):
    """ Represents a running/ran process with enhanced cleanup """

    @staticmethod
    def devnull():
        """ Helper method for opening devnull """
        return open('/dev/null', 'w')

    @staticmethod
    def call(command, cwd=None, shell=False):
        """ Calls a command (either string or list of args). Returns (stdout, stderr) """
        if type(command) is not str or ' ' in command or shell:
            shell = True
            if Configuration.verbose > 1:
                Color.pe(f'\n {{C}}[?] {{W}} Executing (Shell): {{B}}{command}{{W}}')
        else:
            shell = False
            if Configuration.verbose > 1:
                Color.pe(f'\n {{C}}[?]{{W}} Executing: {{B}}{command}{{W}}')

        with Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell) as pid:
            out, err = pid.communicate()

        if isinstance(out, bytes):
            out = out.decode('utf-8', errors='replace')
        if isinstance(err, bytes):
            err = err.decode('utf-8', errors='replace')

        if Configuration.verbose > 1 and out.strip():
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(out.strip().split('\n')))
        if Configuration.verbose > 1 and err.strip():
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(err.strip().split('\n')))

        return out, err

    @staticmethod
    def exists(program):
        if Configuration.initialized and program in set(Configuration.existing_commands.keys()):
            return Configuration.existing_commands[program]

        p2 = Process(['which', program])
        stdout = p2.stdout().strip()
        stderr = p2.stderr().strip()

        exist = not stdout == stderr == ''
        if Configuration.initialized:
            Configuration.existing_commands.update({program: exist})
        return exist

    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0, stdin=PIPE):
        if isinstance(command, str):
            command = command.split(' ')

        self.command = command
        self._cleaned_up = False
        self._communicated = False
        self._manager = ProcessManager()
        self._devnull_handles = []

        if Configuration.verbose > 1:
            Color.pe(f'\n {{C}}[?] {{W}} Executing: {{B}}{" ".join(command)}{{W}}')

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
            self._devnull_handles.extend([sout, serr])
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        try:
            self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
        except OSError as e:
            if e.errno == 24:
                ProcessManager().cleanup_all()
                Process.cleanup_zombies()
                time.sleep(0.1)
                self.pid = Popen(command, stdout=sout, stderr=serr, stdin=stdin, cwd=cwd, bufsize=bufsize)
            else:
                raise

        self._manager.register_process(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass

    def get_output(self, timeout=10):
        """ Wait for process to finish, safely collect output """
        if self._communicated:
            return self.out, self.err

        try:
            self.out, self.err = self.pid.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.force_kill()
            try:
                self.out, self.err = self.pid.communicate(timeout=2)
            except Exception:
                self.out, self.err = b'', b''

        if isinstance(self.out, bytes):
            self.out = self.out.decode('utf-8', errors='replace')
        if isinstance(self.err, bytes):
            self.err = self.err.decode('utf-8', errors='replace')

        self._communicated = True

        # Explicitly close pipes
        for stream in (self.pid.stdin, self.pid.stdout, self.pid.stderr):
            if stream and not stream.closed:
                try:
                    stream.close()
                except Exception:
                    pass

        # Close any devnull handles
        for fh in self._devnull_handles:
            try:
                fh.close()
            except Exception:
                pass
        self._devnull_handles.clear()

        return self.out, self.err

    def stdout(self):
        self.get_output()
        if Configuration.verbose > 1 and self.out and self.out.strip():
            Color.pe('{P} [stdout] %s{W}' % '\n [stdout] '.join(self.out.strip().split('\n')))
        return self.out

    def stderr(self):
        self.get_output()
        if Configuration.verbose > 1 and self.err and self.err.strip():
            Color.pe('{P} [stderr] %s{W}' % '\n [stderr] '.join(self.err.strip().split('\n')))
        return self.err

    def stdoutln(self):
        if getattr(self.pid, "stdout", None):
            return self.pid.stdout.readline()
        return b''

    def stderrln(self):
        if getattr(self.pid, "stderr", None):
            return self.pid.stderr.readline()
        return b''

    def stdin(self, text):
        if getattr(self.pid, "stdin", None):
            try:
                self.pid.stdin.write(text.encode('utf-8'))
                self.pid.stdin.flush()
            except Exception:
                pass

    def poll(self):
        return self.pid.poll()

    def wait(self):
        self.pid.wait()

    def running_time(self):
        return int(time.time() - self.start_time)

    def cleanup(self):
        """Safely clean up subprocess and file descriptors"""
        if getattr(self, '_cleaned_up', False):
            return

        try:
            if hasattr(self, 'pid') and self.pid and self.pid.poll() is None:
                self.interrupt()
        except Exception:
            pass

        # Ensure all descriptors closed
        for stream in (getattr(self.pid, 'stdin', None), getattr(self.pid, 'stdout', None), getattr(self.pid, 'stderr', None)):
            if stream and not stream.closed:
                try:
                    stream.close()
                except Exception:
                    pass

        for fh in getattr(self, '_devnull_handles', []):
            try:
                fh.close()
            except Exception:
                pass
        self._devnull_handles = []

        try:
            self._manager.unregister_process(self)
        except Exception:
            pass

        self._cleaned_up = True

    def interrupt(self, wait_time=2.0):
        if not hasattr(self, 'pid') or not self.pid:
            return
        try:
            self._graceful_shutdown(wait_time)
        except Exception:
            try:
                self.pid.wait()
            except Exception:
                pass

    def _graceful_shutdown(self, wait_time):
        if self.pid.poll() is not None:
            return
        pid = self.pid.pid
        cmd = ' '.join(self.command) if isinstance(self.command, list) else str(self.command)

        if Configuration.verbose > 1:
            Color.pe(f'\n {{C}}[?] {{W}} sending interrupt to PID {pid} ({cmd})')

        try:
            os.kill(pid, signal.SIGINT)
        except OSError:
            return

        start_time = time.time()
        while self.pid.poll() is None and (time.time() - start_time) < wait_time:
            time.sleep(0.1)

        if self.pid.poll() is None:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
            except OSError:
                pass

        if self.pid.poll() is None:
            try:
                os.kill(pid, signal.SIGKILL)
                self.pid.kill()
            except OSError:
                pass

        try:
            self.pid.wait()
        except Exception:
            pass

    def force_kill(self):
        if not hasattr(self, 'pid') or not self.pid:
            return
        try:
            if self.pid.poll() is None:
                self.pid.kill()
                self.pid.wait()
        except Exception:
            pass

    def is_running(self):
        return hasattr(self, 'pid') and self.pid and self.pid.poll() is None

    @staticmethod
    def cleanup_zombies():
        try:
            while True:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
        except Exception:
            pass

    @staticmethod
    def get_open_fd_count():
        try:
            proc_fd_dir = f'/proc/{os.getpid()}/fd'
            if os.path.exists(proc_fd_dir):
                return len(os.listdir(proc_fd_dir))
        except Exception:
            pass
        return -1

    @staticmethod
    def check_fd_limit():
        try:
            import resource
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            current = Process.get_open_fd_count()
            if current > 0 and current > (soft * 0.8):
                Color.pl(f'\n{{!}} {{O}}Warning: High file descriptor usage ({current}/{soft}){{W}}')
                ProcessManager().cleanup_all()
                Process.cleanup_zombies()
                return True
        except:
            pass
        return False


if __name__ == '__main__':
    Configuration.initialize(False)
    p = Process('ls')
    print(p.stdout())
    print(p.stderr())
    p.interrupt()

    out, err = Process.call(['ls', '-lah'])
    print(out, err)

    out, err = Process.call('ls -l | head -2')
    print(out, err)

    print(f'"reaver" exists: {Process.exists("reaver")}')

    p = Process('yes')
    print('Running yes...')
    time.sleep(1)
    print('yes should stop now')

