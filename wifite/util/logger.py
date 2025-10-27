#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Centralized logging utility for wifite2.
Provides consistent logging across all modules with proper exception handling.
"""

import os
import sys
import time
import traceback
from datetime import datetime
from typing import Optional


class Logger:
    """
    Centralized logger for wifite2.
    
    Provides different log levels and handles both console and file output.
    """
    
    # Log levels
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    
    _instance = None
    _log_file = None
    _log_level = INFO
    _verbose = 0
    _enabled = True
    
    def __init__(self):
        """Initialize logger (singleton pattern)."""
        if Logger._instance is not None:
            raise RuntimeError("Logger is a singleton. Use Logger.get_instance()")
        Logger._instance = self
    
    @classmethod
    def get_instance(cls):
        """Get or create logger instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    @classmethod
    def initialize(cls, log_file: Optional[str] = None, verbose: int = 0, enabled: bool = True):
        """
        Initialize the logger with configuration.
        
        Args:
            log_file: Path to log file (None = no file logging)
            verbose: Verbosity level (0-3)
            enabled: Whether logging is enabled
        """
        cls._log_file = log_file
        cls._verbose = verbose
        cls._enabled = enabled
        
        # Set log level based on verbosity
        if verbose >= 3:
            cls._log_level = cls.DEBUG
        elif verbose >= 2:
            cls._log_level = cls.INFO
        elif verbose >= 1:
            cls._log_level = cls.WARNING
        else:
            cls._log_level = cls.ERROR
        
        # Create log file if specified
        if log_file:
            try:
                log_dir = os.path.dirname(log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, mode=0o700)
                
                # Write header
                with open(log_file, 'a') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"Wifite2 Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*80}\n")
            except (OSError, IOError) as e:
                print(f"Warning: Could not create log file {log_file}: {e}", file=sys.stderr)
                cls._log_file = None
    
    @classmethod
    def _should_log(cls, level: int) -> bool:
        """Check if message should be logged based on level."""
        return cls._enabled and level >= cls._log_level
    
    @classmethod
    def _format_message(cls, level: str, module: str, message: str) -> str:
        """Format log message with timestamp and level."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"[{timestamp}] [{level:8s}] [{module:20s}] {message}"
    
    @classmethod
    def _write_to_file(cls, formatted_message: str):
        """Write message to log file."""
        if not cls._log_file:
            return
        
        try:
            with open(cls._log_file, 'a') as f:
                f.write(formatted_message + '\n')
        except (OSError, IOError) as e:
            # Can't log to file, print to stderr as fallback
            print(f"Log file write error: {e}", file=sys.stderr)
    
    @classmethod
    def debug(cls, module: str, message: str):
        """Log debug message."""
        if not cls._should_log(cls.DEBUG):
            return
        
        formatted = cls._format_message('DEBUG', module, message)
        cls._write_to_file(formatted)
        
        if cls._verbose >= 3:
            print(formatted, file=sys.stderr)
    
    @classmethod
    def info(cls, module: str, message: str):
        """Log info message."""
        if not cls._should_log(cls.INFO):
            return
        
        formatted = cls._format_message('INFO', module, message)
        cls._write_to_file(formatted)
        
        if cls._verbose >= 2:
            print(formatted, file=sys.stderr)
    
    @classmethod
    def warning(cls, module: str, message: str):
        """Log warning message."""
        if not cls._should_log(cls.WARNING):
            return
        
        formatted = cls._format_message('WARNING', module, message)
        cls._write_to_file(formatted)
        
        if cls._verbose >= 1:
            print(formatted, file=sys.stderr)
    
    @classmethod
    def error(cls, module: str, message: str, exc: Optional[Exception] = None):
        """
        Log error message with optional exception.
        
        Args:
            module: Module name
            message: Error message
            exc: Optional exception object
        """
        if not cls._should_log(cls.ERROR):
            return
        
        formatted = cls._format_message('ERROR', module, message)
        cls._write_to_file(formatted)
        print(formatted, file=sys.stderr)
        
        # Log exception details if provided
        if exc:
            exc_details = f"Exception: {type(exc).__name__}: {str(exc)}"
            cls._write_to_file(f"  {exc_details}")
            
            if cls._verbose >= 2:
                print(f"  {exc_details}", file=sys.stderr)
            
            # Log full traceback to file
            if cls._log_file:
                try:
                    with open(cls._log_file, 'a') as f:
                        f.write("  Traceback:\n")
                        for line in traceback.format_tb(exc.__traceback__):
                            f.write(f"    {line}")
                except (OSError, IOError):
                    pass
    
    @classmethod
    def critical(cls, module: str, message: str, exc: Optional[Exception] = None):
        """
        Log critical error message.
        
        Args:
            module: Module name
            message: Critical error message
            exc: Optional exception object
        """
        formatted = cls._format_message('CRITICAL', module, message)
        cls._write_to_file(formatted)
        print(formatted, file=sys.stderr)
        
        # Always log exception details for critical errors
        if exc:
            exc_details = f"Exception: {type(exc).__name__}: {str(exc)}"
            cls._write_to_file(f"  {exc_details}")
            print(f"  {exc_details}", file=sys.stderr)
            
            # Log full traceback
            if cls._log_file:
                try:
                    with open(cls._log_file, 'a') as f:
                        f.write("  Traceback:\n")
                        traceback.print_exc(file=f)
                except (OSError, IOError):
                    pass
            
            # Print traceback to stderr if verbose
            if cls._verbose >= 1:
                traceback.print_exc(file=sys.stderr)
    
    @classmethod
    def exception(cls, module: str, message: str):
        """
        Log exception with full traceback.
        Convenience method that captures current exception.
        
        Args:
            module: Module name
            message: Context message
        """
        exc_type, exc_value, exc_tb = sys.exc_info()
        if exc_value:
            cls.error(module, message, exc_value)
        else:
            cls.error(module, message)


# Convenience functions for common use cases
def log_debug(module: str, message: str):
    """Log debug message."""
    Logger.debug(module, message)


def log_info(module: str, message: str):
    """Log info message."""
    Logger.info(module, message)


def log_warning(module: str, message: str):
    """Log warning message."""
    Logger.warning(module, message)


def log_error(module: str, message: str, exc: Optional[Exception] = None):
    """Log error message."""
    Logger.error(module, message, exc)


def log_critical(module: str, message: str, exc: Optional[Exception] = None):
    """Log critical error."""
    Logger.critical(module, message, exc)


def log_exception(module: str, message: str):
    """Log current exception."""
    Logger.exception(module, message)
