import hashlib

password_blacklist = ["'-'", "' '", "'&'", "'^'", "'*'", "' or ''-'", "' or '' '", "' or ''&'", "' or ''^'", "' or ''*'", '"-"', '" "', '"&"', '"^"', '"*"', '" or ""-"', '" or "" "', '" or ""&"', '" or ""^"', '" or ""*"', 'or true--', '" or true--', "' or true--", '") or true--', "') or true--", "' or 'x'='x", "') or ('x')=('x", "')) or (('x'))=(('x", '" or "x"="x', '") or ("x")=("x', '")) or (("x"))=(("x', 'or 1=1', 'or 1=1--', 'or 1=1#', 'or 1=1/*', "admin' --", "admin' #", "admin'/*", "admin' or '1'='1", "admin' or '1'='1'--", "admin' or '1'='1'#", "admin' or '1'='1'/*", "admin'or 1=1 or ''='", "admin' or 1=1", "admin' or 1=1--", "admin' or 1=1#", "admin' or 1=1/*", "admin') or ('1'='1", "admin') or ('1'='1'--", "admin') or ('1'='1'#", "admin') or ('1'='1'/*", "admin') or '1'='1", "admin') or '1'='1'--", "admin') or '1'='1'#", "admin') or '1'='1'/*", "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055", 'admin" --', 'admin" #', 'admin"/*', 'admin" or "1"="1', 'admin" or "1"="1"--', 'admin" or "1"="1"#', 'admin" or "1"="1"/*', 'admin"or 1=1 or ""="', 'admin" or 1=1', 'admin" or 1=1--', 'admin" or 1=1#', 'admin" or 1=1/*', 'admin") or ("1"="1', 'admin") or ("1"="1"--', 'admin") or ("1"="1"#', 'admin") or ("1"="1"/*', 'admin") or "1"="1', 'admin") or "1"="1"--', 'admin") or "1"="1"#', 'admin") or "1"="1"/*', '1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055', "--", '""', "''", 
        "\\\\", "//", ';', ",", "'", '"']
username_blacklist = [
        "\'", "\"", "=", "/", "\\", "--", '""', "''", 
        "\\\\", "//", ';', ",", "'", '"', "&", "%", "^", 
        '*', " ", "   ", ")", "(", '[', ']', '=', '#', 
        '{', "}", "?", "-",
        ]


def hashPassword(password, salt):
    salted_password = salt + password
    return hashlib.md5(salted_password.encode()).hexdigest()


def is_password_malicious(password):
    for passwd_malicious_str in password_blacklist:
        if passwd_malicious_str in password:
            return True
    return False


def is_username_malicious(username):
    for usrn_malicious_str in username_blacklist:
        if usrn_malicious_str in username:
            return True
    return False

