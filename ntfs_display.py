import subprocess
import os

def display_figlet_with_lolcat(text, font):
    figlet_command = ["figlet", "-f", font, "-c", text]
    lolcat_command = ["/usr/games/lolcat"]  # Full path to lolcat command
    
    figlet_process = subprocess.Popen(figlet_command, stdout=subprocess.PIPE)
    lolcat_process = subprocess.Popen(lolcat_command, stdin=figlet_process.stdout, stdout=subprocess.PIPE)
    
    figlet_process.stdout.close()
    
    output, _ = lolcat_process.communicate()
    print(output.decode('utf-8'))

def clear_screen():
    if os.name == 'posix':
        _ = subprocess.call('clear', shell=True)
    elif os.name == 'nt':
        _ = subprocess.call('cls', shell=True)
