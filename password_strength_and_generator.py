import math
import re
import secrets
import string

COMMON_PATTERNS = ("password", "admin", "welcome", "qwerty", "letmein", "123456")

def analyze_password(password: str) -> dict:
    """Evaluate password length, pool entropy, and common predictable patterns."""
    if not password:
        return {"entropy_bits": 0.0, "rating": "Empty", "issues": ["Password is empty"]}

    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    pool_size = (
        (26 if has_lower else 0)
        + (26 if has_upper else 0)
        + (10 if has_digit else 0)
        + (32 if has_symbol else 0)
    ) or 26

    entropy_bits = round(len(password) * math.log2(pool_size), 2)
    issues = []

    if len(password) < 12:
        issues.append("Length is under 12 characters")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains 3+ repeated consecutive characters (e.g., 'aaa')")
    if any(word in password.lower() for word in COMMON_PATTERNS):
        issues.append("Contains a common dictionary word or keyboard walk")

    rating = (
        "Weak" if entropy_bits < 40 or issues else
        "Fair" if entropy_bits < 60 else
        "Good" if entropy_bits < 80 else
        "Strong" if entropy_bits < 100 else
        "Very Strong"
    )
    return {"length": len(password), "entropy_bits": entropy_bits, "rating": rating, "issues": issues}


def generate_secure_password(length: int = 18, exclude_ambiguous: bool = False) -> str:
    """Generate a cryptographically secure password using Python's `secrets` module."""
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        alphabet = "".join(ch for ch in alphabet if ch not in "0O1lI|")

    # Ensure at least one character from each category is present, then shuffle securely
    sys_rng = secrets.SystemRandom()
    chars = [secrets.choice(alphabet) for _ in range(length)]
    sys_rng.shuffle(chars)
    return "".join(chars)


if __name__ == "__main__":
    pwd = generate_secure_password(length=20)
    print(f"Generated: {pwd}")
    print(f"Analysis : {analyze_password(pwd)}")
