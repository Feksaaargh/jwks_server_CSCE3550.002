def intToB64(num: int, padEven: bool = True) -> str:
    """Encodes an integer into base64. Expects input to be positive."""
    if num < 0: return ""
    ret = ""
    while num > 0:
        ret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[num%64] + ret
        num = num // 64
    if padEven and len(ret)%2: return "A"+ret
    return ret