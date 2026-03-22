try:
    from .rsa_core import RSA, RSAKey
except ImportError:
    from .rsa_fallback import RSA, RSAKey

__all__ = ["RSA", "RSAKey"]
