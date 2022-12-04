#!/system/bin/sh
export PATH=$PATH:/system/bin:/system/xbin
if [ `pm path com.noshufou.android.su` != \"\" ]; then am force-stop com.noshufou.android.su; pm uninstall com.noshufou.android.su; fi
if [ `pm path eu.chainfire.su` != \"\" ]; then am force-stop eu.chainfire.su; pm uninstall eu.chainfire.su; fi
if [ `pm path eu.chainfire.supersu` != \"\" ]; then am force-stop eu.chainfire.supersu; pm uninstall eu.chainfire.supersu; fi
if [ -e /data/local.prop ]; then rm /data/local.prop; fi
if [ -e /system/xbin/su ]; then rm /system/xbin/su; fi
if [ -L /system/bin/su ]; then rm /system/bin/su; fi
if [ -e /system/app/Superuser.apk ]; then rm /system/app/Superuser.apk; fi
