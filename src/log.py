from datetime import datetime

current_time = datetime.now()
time_string = current_time.strftime("%Y-%m-%d %H:%M:%S")


color_codes = {
        "black": "\033[30m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
        "reset": "\033[0m"
    }

def get_time():
        current_time = datetime.now()
        time_string = current_time.strftime("%Y-%m-%d %H:%M:%S")
        return time_string

def color_print(message, color, time=True): 
    t = get_time() 
    if time: 
        print(f'{color_codes[color]}[{t}] {color_codes["reset"]}{message}') 
    else: 
        print(f'{color_codes[color]}{message}{color_codes["reset"]}')

class log():

    def black(message,time=True):
        color_print(message,"black",time)
    def red(message,time=True):
        color_print(message,"red",time)

    def green(message, time=True):
        color_print(message, "green", time)

    def yellow(message, time=True):
        color_print(message, "yellow", time)

    def blue(message, time=True):
        color_print(message, "blue", time)

    def magenta(message, time=True):
        color_print(message, "magenta", time)

    def cyan(message, time=True):
        color_print(message, "cyan", time)
