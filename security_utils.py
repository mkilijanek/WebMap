"""
Security utilities for WebMap application
Provides input validation and secure file operations
"""

import os
import re
from django.core.exceptions import SuspiciousFileOperation, ValidationError


def safe_join(base_dir, *paths):
    """
    Safely join paths and ensure result is within base_dir.
    Prevents path traversal attacks.

    Args:
        base_dir: Base directory that result must be within
        *paths: Path components to join

    Returns:
        Absolute path within base_dir

    Raises:
        SuspiciousFileOperation: If path traversal detected
    """
    final_path = os.path.abspath(os.path.join(base_dir, *paths))
    base_path = os.path.abspath(base_dir)

    if not final_path.startswith(base_path + os.sep) and final_path != base_path:
        raise SuspiciousFileOperation(
            f'Path traversal detected: attempted to access {final_path} outside {base_path}'
        )

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
    Validate IPv4 address format.

    Args:
        ip_string: IP address string

    Returns:
        Validated IP address

    Raises:
        ValidationError: If not a valid IP address
    """
    import ipaddress

    try:
        ipaddress.IPv4Address(ip_string)
        return ip_string
    except (ValueError, ipaddress.AddressValueError):
        raise ValidationError('Invalid IPv4 address')


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

    # CPE format: cpe:/[o|a|h]:vendor:product:version...
    if not re.match(r'^cpe:/[oah]:[a-zA-Z0-9_\-\.:/]+$', cpe_string):
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


def sanitize_notes_content(content, max_length=10000):
    """
    Sanitize notes content.

    Args:
        content: Notes content
        max_length: Maximum allowed length

    Returns:
        Sanitized content

    Raises:
        ValidationError: If content is invalid
    """
    if not content:
        raise ValidationError('Notes content cannot be empty')

    if len(content) > max_length:
        raise ValidationError(f'Notes content too long (max {max_length} characters)')

    # Basic XSS prevention - remove script tags
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'onerror=',
        r'onload=',
        r'onclick=',
        r'<iframe',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            raise ValidationError('Potentially dangerous content detected')

    return content
