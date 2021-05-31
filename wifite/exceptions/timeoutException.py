#!/usr/bin/env python
# -*- coding: utf-8 -*-

class TimeoutError(Exception):
    def __init__(self, message, errors):
        # Call the base class constructor with the parameters it needs
        super(ValidationError, self).__init__(message)

        # Now for your custom code...
        self.errors = errors


class TimeoutException:
    pass