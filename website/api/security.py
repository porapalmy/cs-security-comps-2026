import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if IP is private (localhost, 192.168.x.x, 10.x.x.x, etc.) or loopback
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
            
        # Also block AWS/Cloud metadata service IP explicitly just in case
        if str(ip_obj) == "169.254.169.254":
            return False
            
        return True
    except Exception:
        # If we can't parse or resolve, it's unsafe
        return False
