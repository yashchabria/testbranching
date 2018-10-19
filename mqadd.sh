#!/bin/sh /etc/rc.common
setup_mq_network()
{
. /lib/functions/system.sh

	# eth0.2 primary mac
	#
 	local	mqwan_mac=`uci get profile.system.base_mac`
        [ "$mqwan_mac" = "unknown" ] && mqwan_mac=$(cat /sys/class/net/eth0.2/address)
    	
		local   mqwan2x_mac=$(macaddr_add "$mqwan_mac" 1)
	local	mqlan_mac=$(macaddr_add "$mqwan_mac" 2)
echo $mqwan_mac

echo mqwan2x_mac
echo $mqlan_mac


echo "Setting up Wireless"

		uci set wireless.ra0.ssid='MQC_SSID_2.4G'
		uci set wireless.mt7620.channel='6'
		#uci set wireless.rai0.ssid='WLRGFM-100_SSID_5G'
		uci set wireless.mt7612e.channel='36'
		uci set wireless.ra0.disabled='0'
		uci set wireless.rai0.disabled='1'
		uci commit wireless


echo "removing existing configuration "

		
		 uci delete network.lan
		 uci delete network.wan
		 uci delete network.wan20
		 uci delete network.wan30

		 uci -c /etc/config/ set   network.wan2x='interface'

		uci -c /etc/config/ set network.wan='interface'

		uci -c /etc/config/ set network.wan.ifname='eth0.2'
		uci -c /etc/config/ set network.wan.proto='dhcp'
		uci -c /etc/config/ set network.wan.wantype='dhcp'
		uci -c /etc/config/ set network.wan.at_port=''
		uci -c /etc/config/ set network.wan.metric=0
		uci -c /etc/config/ set network.wan.macaddr="$mqwan_mac"

		uci commit network

echo "mq setup LAN"		
	if [ "$(uci -c /mnt/data/config/ get mfg.system.wifi_support)" = "1" ]; then
		

		uci -c /etc/config/ set network.lan='interface'
		uci -c /etc/config/ set  network.lan.ifname='ra0'
		uci -c /etc/config/ set  network.lan.force_link='1'
		uci -c /etc/config/ set  network.lan.type=''
		uci -c /etc/config/ set  network.lan.gateway='13.14.15.1'
		uci -c /etc/config/ set  network.lan.dns='13.14.15.1'
		uci -c /etc/config/ set  network.lan.disabled='0'
		uci -c /etc/config/ set  network.lan.ipaddr='13.14.15.1'
		uci -c /etc/config/ set  network.lan.proto='static'
		uci -c /etc/config/ set  network.lan.macaddr="$mqlan_mac"

		uci -c /etc/config/ set   network.wan2x.wantype='extender' 

		uci -c /etc/config/	set network.wan30='interface'
		uci -c /etc/config/	set network.wan30.proto='dhcp'
		uci -c /etc/config/	set network.wan30.wantype='extender'
		uci -c /etc/config/	set network.wan30.ifname='aplci0'
		uci -c /etc/config/ set network.wan30.macaddr="$mqwan2x_mac"
		uci -c /etc/config/ set network.wan30.metric=30
		uci commit network
		route add -net 13.14.15.0/24 gw 127.0.0.1 lo


	fi

	if [ "$(uci -c /mnt/data/config/ get mfg.system.3g_support)" = "1" ]; then
		 
		
		 uci -c /etc/config/	set network.wan20='interface'
		 uci -c /etc/config/	set network.wan20.proto='3g'
		 uci -c /etc/config/	set network.wan20.wanproto='3g'
		 uci -c /etc/config/	set network.wan20.wantype='3g'
		 uci -c /etc/config/	set network.wan20.ifname='3g-wan'
		 uci -c /etc/config/	set network.wan20.apn=m2m005365.attz
		 uci -c /etc/config/	set network.wan20.device=/dev/ttyUSB2
		 uci -c /etc/config/	set network.wan20.at_port=/dev/ttyUSB3
		 uci -c /etc/config/ 	set network.wan2x.wantype='3g' 
		 uci -c /etc/config/ 	set network.wan20.metric=20
		  uci commit network
	fi

		uci commit
}
setup_mq_network
