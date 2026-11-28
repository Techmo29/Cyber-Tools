rule Suspicious_Encoded_Script_Execution
{
    meta:
        description = "Detects base64-encoded commands or dynamic evaluation in scripts"
        severity = "medium"

    strings:
        $ps_enc = "-EncodedCommand" ascii nocase
        $ps_enc_short = "-enc " ascii nocase
        $py_exec = /exec\s*\(\s*base64\.(b64decode|urlsafe_b64decode)/ ascii
        $php_eval = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ ascii nocase
        $sh_pipe = /(curl|wget)\s+[^\n|]+\|\s*(sh|bash)/ ascii

    condition:
        uint16(0) != 0x5A4D and (any of them)
}
