## Add two dependant files: pam.d/common-password & login.defs
## Have them with modifications and referenced in the script, or wget them through a raw github

import os
import time
print("Please run as root in your users home directory")
class auto:
    def __init__(self):
        ## List of runnable things. Used later with eval(str(self.options[x])).
        self.options={1:'robot.update()', 2:'robot.users()', 3:'robot.files_soft()', 4:'robot.firewall()', 5:''}
        while True:
            ## These are the options
            print("1. Update, 2. Users, 3. Files+Software, 4. Firewall+antivirus, 5. ")
            self.preform=int(input("Enter a number, 1 thru %s " % len(self.options)))
            if self.preform in self.options:
                break
        
    def update(self):
        os.popen('sudo add-apt-repository -y ppa:libreoffice/ppa')
        os.wait()
        os.popen('sudo apt-get update && sudo apt-get upgrade')
        os.wait()
        os.popen('sudo apt-get dist-upgrade -y')
        os.wait()
        os.popen('sudo apt-get --purge --reinstall install firefox -y')
        os.wait()
        os.popen('sudo apt-get autoclean')
        os.wait()
        os.popen('sudo apt-get install --only-upgrade bash')
        os.wait()
        os.popen('sudo apt-get upgrade')
        os.wait()
        print("Go to the updates manager, and set updates to daily and add security updates. Then, rerun updates")

    def files_soft():
        ftypes=['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.zip', '.php', '.tar.gz', '.html']
        for x in range(0, len(ftypes)):
            os.popen('sudo find /home/ -name *"%s" >> ~/Desktop/files' % ftypes[x])
        print("All strange file paths have been sent to the Desktop")
        os.popen('sudo apt-get remove --purge *game*')
        os.wait()
        os.popen('sudo apt-get remove --purge nmap zenmap')
    def firewall(self):
        os.popen('sudo apt-get install clamtk -y')
        os.wait()
        os.popen('sudo apt-get install ufw')
        os.wait()
        os.popen('sudo ufw enable')
        os.wait()
        os.popen('clamscan -r /home/')
        os.wait()

    def users(self):
        users=os.popen('compgen -u').read().split()
        ##append authorized users to the 'auth' list >
        auth='''root
        daemon
        bin
        sys
        sync
        games
        man
        lp
        mail
        news
        uucp
        proxy
        www-data
        backup
        list
        irc
        gnats
        nobody
        systemd-network
        systemd-resolve
        systemd-timesync
        messagebus
        syslog
        _apt
        tss
        uuidd
        tcpdump
        avahi-autoipd
        usbmux
        rtkit
        dnsmasq
        cups-pk-helper
        lightdm
        speech-dispatcher
        avahi
        kernoops
        saned
        hplip
        whoopsie
        colord
        pulse
        systemd-coredump
        '''.split()
        for i in range(0, len(users)):
            if users[i] not in auth:
                print(users[i])

        
        os.popen('touch ~/Desktop/admins')
        os.popen('cat /etc/passwd | grep sudo >> ~/Desktop/admins')
        print('List of admins moved to ~/Desktop/admins')
    
    def run(self):
        eval(str(self.options[self.preform]))

robot=auto()
robot.run()
