import os
users=os.popen('cut -d: -f1 /etc/passwd').read().split()
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
