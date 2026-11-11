#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Exceptions that describe conditions the user can act on."""


class WifiteError(RuntimeError):
    """A failure caused by the environment or the arguments, not a crash.

    The top-level handler prints the message without a traceback for these;
    anything else keeps its stack so genuine bugs stay debuggable. The
    RuntimeError base keeps existing callers that catch that type working.
    """