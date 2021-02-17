import colorama
from colorama import Fore, Style

def print_block(text, border_length, character='*'):
    length = len(text) + 2
    print((2 * border_length + length) * character)
    print(border_length * character + ' ' + text +  ' ' + border_length * character)
    print((2 * border_length + length) * character)

def print_underlined(text):
    print("\033[4m" + text + "\033[0m")

def report(thing, condition, success, failure, tabbed_failure = False):
    green_plus = Fore.GREEN + "[+] " + Style.RESET_ALL
    red_exclamation = Fore.RED + "[!] " + Style.RESET_ALL
    if not condition(thing):
        print(green_plus + success)
    else: 
        if tabbed_failure:
            print(end='')
        print(red_exclamation + failure)

def cookie_report(thing, condition, success, failure, tabbed_failure = False):
    green_plus = Fore.GREEN + "[+] " + Style.RESET_ALL
    red_exclamation = Fore.RED + "[!] " + Style.RESET_ALL
    if not condition(thing):
        print(red_exclamation + failure)
    else: 
        if tabbed_failure:
            print(end='')
        print(green_plus + success)
