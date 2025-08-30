from datetime import datetime

def is_valid_south_african_id(id_str: str) -> bool:
    """
    Basic plausibility + Luhn-like checksum on SA ID (13 digits).
    This follows common Luhn-style verification used in practice.
    """
    if not id_str or len(id_str) != 13 or not id_str.isdigit():
        return False

    # Validate YYMMDD date plausibility (not perfect for all edge cases)
    yy = int(id_str[0:2])
    mm = int(id_str[2:4])
    dd = int(id_str[4:6])

    # For plausible year, map 00-99 to 1900-2099 and try to validate date
    # We'll just try two possibilities to avoid false negative on century
    valid_date = False
    for century in (1900, 2000):
        try:
            datetime(century + yy, mm, dd)
            valid_date = True
            break
        except ValueError:
            continue
    if not valid_date:
        return False

    # Luhn-like checksum calculation on first 12 digits
    digits = [int(d) for d in id_str]
    total = 0
    for i in range(12):
        d = digits[i]
        # Double every second digit from the right would be Luhn; here we follow a commonly used pattern
        if (i % 2) == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - (total % 10)) % 10
    return check == digits[12]
