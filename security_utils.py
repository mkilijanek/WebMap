"""
Security utilities for WebMap application
Provides input validation and secure file operations
"""

import base64
import binascii
import ipaddress
import os
import re
from urllib.parse import unquote

from django.core.exceptions import SuspiciousFileOperation, ValidationError


def safe_join(base_dir, *paths):
    """
    Safely join paths and ensure result is within base_dir.
    Prevents path traversal attacks. Symlinks are resolved first, so a link
    inside base_dir cannot point the result somewhere else.

    Args:
        base_dir: Base directory that result must be within
        *paths: Path components to join

    Returns:
        Absolute path within base_dir

    Raises:
        SuspiciousFileOperation: If path traversal detected
    """
    base_path = os.path.realpath(base_dir)
    final_path = os.path.realpath(os.path.join(base_path, *paths))

    if os.path.commonpath([base_path, final_path]) != base_path:
        raise SuspiciousFileOperation('Path traversal detected')

    return final_path


def validate_filename(filename, max_length=255):
    """
    Validate filename contains only safe characters.
    Prevents path traversal and command injection via filenames.

    Args:
        filename: Filename to validate
        max_length: Maximum allowed filename length

    Returns:
        Validated filename

    Raises:
        ValidationError: If filename is invalid
    """
    if not filename:
        raise ValidationError('Filename cannot be empty')

    if len(filename) > max_length:
        raise ValidationError(f'Filename too long (max {max_length} characters)')

    # Allow only alphanumeric, dash, underscore, and dot
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise ValidationError(
            'Filename contains invalid characters. Only alphanumeric, dash, underscore, and dot allowed.'
        )

    # Prevent path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValidationError('Path traversal patterns detected in filename')

    # Prevent hidden files
    if filename.startswith('.'):
        raise ValidationError('Hidden files not allowed')

    return filename


def validate_md5_hash(hash_string):
    """
    Validate MD5 hash format.

    Args:
        hash_string: String to validate as MD5 hash

    Returns:
        Validated hash string (lowercase)

    Raises:
        ValidationError: If not a valid MD5 hash
    """
    if not hash_string:
        raise ValidationError('Hash cannot be empty')

    if not re.match(r'^[a-fA-F0-9]{32}$', hash_string):
        raise ValidationError('Invalid MD5 hash format')

    return hash_string.lower()


def validate_port_number(port_string):
    """
    Validate port number.

    Args:
        port_string: Port number as string

    Returns:
        Port number as integer

    Raises:
        ValidationError: If not a valid port number
    """
    try:
        port = int(port_string)
        if port < 1 or port > 65535:
            raise ValidationError('Port number must be between 1 and 65535')
        return port
    except (ValueError, TypeError):
        raise ValidationError('Invalid port number')


def validate_ip_address(ip_string):
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip_string: IP address string

    Returns:
        Validated IP address

    Raises:
        ValidationError: If not a valid IP address
    """
    try:
        ipaddress.ip_address(ip_string)
        return ip_string
    except (ValueError, TypeError):
        raise ValidationError('Invalid IP address')


def validate_host_address(value):
    """
    Validate a host identifier as used by the reports: an IPv4 or IPv6
    address, or a MAC address for hosts nmap reported without an IP.
    """
    if isinstance(value, str) and re.match(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$', value):
        return value
    return validate_ip_address(value)


def validate_cpe_string(cpe_string, max_length=200):
    """
    Validate CPE (Common Platform Enumeration) string format.

    Args:
        cpe_string: CPE string to validate
        max_length: Maximum allowed length

    Returns:
        Validated CPE string

    Raises:
        ValidationError: If CPE string is invalid
    """
    if not cpe_string:
        raise ValidationError('CPE string cannot be empty')

    if len(cpe_string) > max_length:
        raise ValidationError(f'CPE string too long (max {max_length} characters)')

    # CPE 2.2 URI: cpe:/[o|a|h]:vendor:product:version... No '/' after the
    # prefix and no '..', so the value cannot add path segments to the
    # CVE API URL it is appended to.
    if not re.match(r'^cpe:/[oah](:[A-Za-z0-9_\-\.~+]*)+$', cpe_string) or '..' in cpe_string:
        raise ValidationError('Invalid CPE format')

    return cpe_string


def validate_label(label):
    """
    Validate label value.

    Args:
        label: Label string

    Returns:
        Validated label

    Raises:
        ValidationError: If label is invalid
    """
    allowed_labels = ['Vulnerable', 'Critical', 'Warning', 'Checked']

    if label not in allowed_labels:
        raise ValidationError(
            f'Invalid label. Allowed values: {", ".join(allowed_labels)}'
        )

    return label


def validate_object_type(obj_type):
    """
    Validate object type.

    Args:
        obj_type: Object type string

    Returns:
        Validated object type

    Raises:
        ValidationError: If object type is invalid
    """
    allowed_types = ['host', 'port']

    if obj_type not in allowed_types:
        raise ValidationError(
            f'Invalid object type. Allowed values: {", ".join(allowed_types)}'
        )

    return obj_type



def validate_notes_b64(value, max_length=10240):
    """
    Validate notes as sent by the UI: urlencoded base64 of UTF-8 text.

    Raises:
        ValidationError: If notes are too long or not urlencoded base64
    """
    if len(value) > max_length:
        raise ValidationError(f'Notes content too large (max {max_length} bytes)')

    if not re.match(r'^[A-Za-z0-9%+/=]*$', value):
        raise ValidationError('Invalid notes encoding')

    try:
        base64.b64decode(unquote(value), validate=True).decode('utf-8')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ValidationError('Invalid notes encoding')

    return value
