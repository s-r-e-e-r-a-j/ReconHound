import os
import sys

if os.geteuid() != 0:
    print("please run as root or with sudo")
    sys.exit(1)
choice = input('[+] to install press (Y) to uninstall press (N) >> ')
run = os.system
if str(choice) =='Y' or str(choice)=='y':

    run('chmod 777 reconhound.py')
    run('mkdir /usr/share/reconhound')
    run('cp reconhound.py /usr/share/reconhound/reconhound.py')

    cmnd=(' #! /bin/sh \n exec python3 /usr/share/reconhound/reconhound.py "$@"')
    with open('/usr/bin/reconhound','w')as file:
        file.write(cmnd)
    run('chmod +x /usr/bin/reconhound & chmod +x /usr/share/reconhound/reconhound.py')
    print('''\n\ncongratulation ReconHound is installed successfully \nfrom now just type \x1b[6;30;42mreconhound\x1b[0m in terminal ''')
if str(choice)=='N' or str(choice)=='n':
    run('rm -r /usr/share/reconhound ')
    run('rm /usr/bin/reconhound ')
    print('[!] now ReconHound has been removed successfully')
