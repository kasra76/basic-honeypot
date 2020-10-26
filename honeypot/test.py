from web.utilities import  is_password_malicious


t = "' sdhi UNION ' '"


print(is_password_malicious(t))