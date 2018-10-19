#!/bin/sh
#iwpriv ra0 get_site_survey

WIFI=$1
SSID=$2
CHANNEL=$3
/etc/init.d/wifiscan reload
uci set wireless.apcli0.disabled=0
uci set wireless.apcli0.ssid="$WIFI"
uci set wireless.apcli0.encryption=psk2+aes
uci set wireless.apcli0.key="$SSID"
uci set wireless.mt7620.channel="$CHANNEL"
uci commit

/etc/init.d/wifi7620  stop

echo " Network restart "
/etc/init.d/network restart
