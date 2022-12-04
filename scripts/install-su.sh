#!/system/bin/sh
export PATH=$PATH:/system/bin:/system/xbin
cp /data/local/tmp/su /system/xbin/su
chown root:root /system/xbin/su
chmod 6755 /system/xbin/su
ln -s /system/xbin/su /system/bin/su
cp /data/local/tmp/Superuser.apk /system/app/Superuser.apk
chown root:root /system/app/Superuser.apk
chmod 644 /system/app/Superuser.apk
pm install /system/app/Superuser.apk