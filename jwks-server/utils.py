def intToB64(num: int) -> str:
    """Encodes an integer into base64. Expects input to be positive."""
    if num < 0: return ""
    if num == 0: return "A"  # below loop does not work with input of 0
    ret = ""
    while num > 0:
        ret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[num%64] + ret
        num = num // 64
    return ret