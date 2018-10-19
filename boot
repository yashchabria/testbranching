#!/bin/sh /etc/rc.common
# Copyright (C) 2006-2011 OpenWrt.org

START=10

. /lib/functions/custom.sh
. /lib/functions/system.sh

mount_data_jffs2() {
	local data_dir="/mnt/data"
	local data_index=`cat /proc/mtd | grep -nw data | cut -f 1 -d':'`
	local data_mtd_index=`expr $data_index - 2`
	local data_mtd_char="/dev/mtd"$data_mtd_index
	local data_mtd_block="/dev/mtdblock"$data_mtd_index

	mkdir -p $data_dir

	local fstype=`echo $(hexdump -s 0 -n 3 -e '16/1 "%c"' $data_mtd_char)`
	if [ "$fstype" != "UBI" ]; then
		mount -t jffs2 $data_mtd_block $data_dir
	else
		echo "WARN >> detected ubifs on $data_mtd_char, rebuild jffs2" > /dev/console
		/bin/false;
	fi

	[ "$?" != "0" ] && {
		#mkdir -p $tmp_dir
		#mkfs.jffs2 -X rtime -X lzma -x zlib  --root=$tmp_dir --eraseblock=0x10000 -b -o $tmp_jffs2 --pad=4194304
		mtd erase $data_mtd_char
		#mtd jffs2write $tmp_jffs2 $data_mtd_char
		mount -t jffs2 $data_mtd_block $data_dir
	}
}

mount_data_ubifs () {
	local data_dir="/mnt/data"
	local data_index=`cat /proc/mtd | grep -nw data | cut -f 1 -d':'`
	local data_mtd_index=`expr $data_index - 2`
	local data_mtd_char="/dev/mtd"$data_mtd_index
	local data_mtd_block="/dev/mtdblock"$data_mtd_index

	local data_size_mb=300
	local data_vol_name="data"

	# mount ubifs
	echo "INFO >> prepare ubifs" > /dev/console
	if [ ! -f /dev/ubi_ctrl ]; then
		local mj=`cat /sys/class/misc/ubi_ctrl/dev | awk -F ':' '{print $1}'`
		local mr=`cat /sys/class/misc/ubi_ctrl/dev | awk -F ':' '{print $2}'`
		mknod /dev/ubi_ctrl c $mj $mr
	fi

	echo "INFO >> ubiattach mtd$data_mtd_index" > /dev/console
	ubiattach /dev/ubi_ctrl -m $data_mtd_index
	if [ "$?" = "0" ] && [ ! -f /dev/ubi0 ]; then
		local mj=`cat /proc/devices | grep ubi0 | awk '{print $1}'`
		mknod -m 644 /dev/ubi0 c $mj 0
	fi

	if [ ! -f /dev/ubi0_0 ]; then
		local mj=`cat /proc/devices | grep ubi0 | awk '{print $1}'`
		mknod -m 644 /dev/ubi0_0 c $mj 1
	fi

	echo "INFO >> mounting ubifs" > /dev/console
	mkdir -p $data_dir
	mount -t ubifs /dev/ubi0_0 $data_dir

	[ "$?" != "0" ] && {
		echo "WARN >> mount ubifs fail...rebuild ubifs" > /dev/console
		rm -f /dev/ubi0 /dev/ubi0_0
		#flash_erase $data_mtd_char 0 0
		mtd erase $data_mtd_char
		ubiformat -y -q $data_mtd_char -s 2048

		ubiattach /dev/ubi_ctrl -m $data_mtd_index
		if [ ! -f /dev/ubi0 ]; then
			local mj=`cat /proc/devices | grep ubi0 | awk '{print $1}'`
			mknod -m 644 /dev/ubi0 c $mj 0
		fi

		ubimkvol /dev/ubi0 -s "${data_size_mb}MiB" -N $data_vol_name
		if [ ! -f /dev/ubi0_0 ]; then
			local mj=`cat /proc/devices | grep ubi0 | awk '{print $1}'`
			mknod -m 644 /dev/ubi0_0 c $mj 1
		fi
		mkdir -p $data_dir
		mount -t ubifs /dev/ubi0_0 $data_dir
		if [ "$?" != "0" ]; then
			echo "ERR >> rebuild ubifs FAIL!!" > /dev/console
		else
			echo "INFO >> rebuild ubifs done" > /dev/console
		fi
	}
}

setup_dirs_n_files() {
	mkdir -p /var/run
	mkdir -p /var/log
	mkdir -p /var/lock
	mkdir -p /var/state
	mkdir -p /tmp/.uci
	chmod 0700 /tmp/.uci
	touch /var/log/wtmp
	touch /var/log/lastlog
	touch /tmp/resolv.conf.auto
	ln -sf /tmp/resolv.conf.auto /tmp/resolv.conf
	grep -q debugfs /proc/filesystems && /bin/mount -o noatime -t debugfs debugfs /sys/kernel/debug
	[ "$FAILSAFE" = "true" ] && touch /tmp/.failsafe

	# rcConfd path
	mkdir -p /var/run/rcConfd

	# busycat log
	mkdir -p /var/busycat
	mkdir -p /var/busycat/log
	echo "/dev/console" > /var/busycat/logout
	echo "3" > /var/busycat/loglevel
	#touch /var/busycat/log/all

	# setup data partition
	mkdir -p /mnt/data/config
	mkdir -p /mnt/data/app
}

setup_mfg_config() {
	[ ! -f /mnt/data/config/mfg ] && {
		echo "boot: generating mfg config" > /dev/console
		touch /mnt/data/config/mfg
		uci -c /mnt/data/config/ set mfg.system='section'
		uci -c /mnt/data/config/ set mfg.system.base_mac='unknown'
		uci -c /mnt/data/config/ set mfg.system.sn='GMK952700000001'

		# 840:US, ISO-3166 https://en.wikipedia.org/wiki/Country_code
		uci -c /mnt/data/config/ set mfg.system.country_code='TW' 

		uci -c /mnt/data/config/ set mfg.system.hw_version='V01'
		uci -c /mnt/data/config/ set mfg.system.model_name='MACHINEQ_LORA'

		# mode= {development, production, testing, debug}
		uci -c /mnt/data/config/ set mfg.system.mode='mfg'

		uci -c /mnt/data/config/ set mfg.system.cloud_pin='unknown'
		uci -c /mnt/data/config/ set mfg.system.wifi_support='1'
		uci -c /mnt/data/config/ set mfg.system.3g_support='0'
		uci -c /mnt/data/config/ set mfg.system.edu_ver_flag='0'

		uci -c /mnt/data/config/ commit
	}
}
setup_mq_network()
{
	# eth0.2 primary mac
	#
 	local	mqwan_mac=`uci get profile.system.base_mac`
        [ "$mqwan_mac" = "unknown" ] && mqlan_mac=$(cat /sys/class/net/eth0/address)
    local   mqwan2x_mac=$(macaddr_add "$mqlan_mac" 1)
	local	mqlan_mac=$(macaddr_add "$mqlan_mac" 2)

		uci set wireless.ra0.ssid='MQC_SSID_2.4G'
		uci set wireless.mt7620.channel='6'
		#uci set wireless.rai0.ssid='WLRGFM-100_SSID_5G'
		uci set wireless.mt7612e.channel='36'
		uci set wireless.ra0.disabled='0'
		uci set wireless.rai0.disabled='1'
		uci commit wireless


		
		 uci delete network.lan
		 uci delete network.wan
		 uci delete network.wan20
		 uci delete network.wan30

		uci -c /etc/config/ set network.interface='wan'
		uci -c /etc/config/	set network.wan.ifname='eth0.2'
		uci -c /etc/config/ set network.wan='interface'
		uci -c /etc/config/ set network.wan.proto='dhcp'
		uci -c /etc/config/ set network.wan.wantype='dhcp'
		uci -c /etc/config/ set network.wan.at_port=''
		uci -c /etc/config/ set network.wan.macaddr=$mqwan_mac
		uci commit network

	if [ "$(uci -c /mnt/data/config/ get mfg.system.wifi_support)" = "1" ]; then
		

		uci -c /etc/config/ set network.interface='lan'
		uci -c /etc/config/ set  network.lan.ifname='ra0'
		uci -c /etc/config/ set  network.lan.force_link='1'
		uci -c /etc/config/ set  network.lan.type=''
		uci -c /etc/config/ set  network.lan.gateway='13.14.15.1'
		uci -c /etc/config/ set  network.lan.dns='13.14.15.1'
		uci -c /etc/config/ set  network.lan.disabled='0'
		uci -c /etc/config/ set  network.lan.ipaddr='13.14.15.1'
		uci -c /etc/config/ set  network.lan.proto='static'
		uci -c /etc/config/ set  network.wan.lan=$mqlan_mac

		uci -c /etc/config/ set   network.wan2x.wantype='extender' 

		uci -c /etc/config/	set network.interface='wan30'
		uci -c /etc/config/	set network.wan30.proto='dhcp'
		uci -c /etc/config/	set network.wan30.wantype='extender'
		uci -c /etc/config/	set network.wan30.ifname='aplci0'
		uci -c /etc/config/ set network.wan.macaddr=$mqwan2x_mac
		uci commit network

	fi

	if [ "$(uci -c /mnt/data/config/ get mfg.system.3g_support)" = "1" ]; then
		 
		
		 uci -c /etc/config/	set network.interface='wan20'
		 uci -c /etc/config/	set network.wan30.proto='3g'
		 uci -c /etc/config/	set network.wan30.wanproto='3g'
		 uci -c /etc/config/	set network.wan30.wantype='3g'
		 uci -c /etc/config/	set network.wan30.ifname='3g-wan'
		 uci -c /etc/config/	set network.wan30.apn=m2m005365.attz
		 uci -c /etc/config/	set  network.wan30.device=/dev/ttyUSB2
		 uci -c /etc/config/	set  network.wan30.at_port=/dev/ttyUSB3
		  uci -c /etc/config/ set   network.wan2x.wantype='3g' 
		  uci commit network
	fi

		uci commit
}
check_mfg() {
	local mode=`uci -c /mnt/data/config/ get mfg.system.mode`

	 
	if [ "$mode" = "mfg" ]; then
		
			setup_mq_network


	elif [ "$mode" = "production" ]; then

		local interface=`uci get network.wan.ifname`
		if [[ "$interface" != "apcli0" && "$interface" != "3g-wan" ]]; then
			#uci set network.wan.ifname='eth0.2'
		#	uci set network.lan.ifname=''
		#	uci commit network
		fi
			if [ "$(uci -c /mnt/data/config/ get mfg.system.wifi_support)" = "0" ]; then

				uci set wireless.ra0.disabled='1'
				uci set wireless.rai0.disabled='1'
			uci commit wireless
			else
				uci set wireless.ra0.disabled='0'
				uci set wireless.rai0.disabled='1'
			uci commit wireless
		fi
	fi
}

setup_profile_config() {
	local debug=`uci get profile.system.debug`
	debug=${debug:="0"}

	echo "boot: setup config profile" > /dev/console

	rm -f /etc/config/profile
	touch /etc/config/profile

	uci set profile.system='section'
	uci set profile.system.fw_version=`cat /etc/version | cut -d" " -f 2`
	uci set profile.system.hw_version=`uci -c /mnt/data/config/ get mfg.system.hw_version`
	uci set profile.system.model_name=`uci -c /mnt/data/config/ get mfg.system.model_name`
	uci set profile.system.base_mac=`uci -c /mnt/data/config/ get mfg.system.base_mac`
	uci set profile.system.sn=`uci -c /mnt/data/config/ get mfg.system.sn`
	uci set profile.system.country_code=`uci -c /mnt/data/config/ get mfg.system.country_code`
	uci set profile.system.inet_status='0' # whether the dms_agent connect to server.
	uci set profile.system.debug="$debug"

	# Setup cloud section
	local system_mode=`uci -c /mnt/data/config/ get mfg.system.mode`
	uci set profile.cloud='section'

	# Setup ota section
	uci set profile.ota='section'
	uci set profile.ota.new_fw_version="0.00.0-0"

	# Setup fw_upgrade section
	uci set profile.fw_upgrade='section'
	uci set profile.fw_upgrade.pending='0'
	uci set profile.fw_upgrade.status='finish'

	uci commit profile
}

setup_boot_firmware() {

	echo "boot: setup boot_firmware config" > /dev/console

	# Check /etc/config/boot_firmware
	[ ! -e /etc/config/boot_firmware ] && {
			touch /etc/config/boot_firmware
			uci set boot_firmware.fw_info='section'

			#local cur_run_fw=`fw_printenv running_fw | cut -d'=' -f2`

			local cur_run_fw=`fw_printenv | awk '/running_fw/ {print $4}' | sed -e 's/running_fw=//g' |tr -d '\n'`
			
			if [ "$cur_run_fw" = "firmware2" ]; then
				uci set boot_firmware.fw_info.primary="fw2"
			else
				uci set boot_firmware.fw_info.primary="fw1"
			fi

			uci set boot_firmware.fw_info.fw1_ver="-"
			uci set boot_firmware.fw_info.fw2_ver="-"
        	}

	# Setup fw_info section
	uci set boot_firmware.fw_info='section'
	if [ "$(uci get boot_firmware.fw_info.primary)" = "fw2" ]; then
		uci set boot_firmware.fw_info.fw2_ver=`cat /etc/version | cut -d" " -f 2`
	else
		uci set boot_firmware.fw_info.fw1_ver=`cat /etc/version | cut -d" " -f 2`
	fi

}

uci_apply_defaults() {
	. /lib/functions/system.sh

	cd /etc/uci-defaults || return 0
	files="$(ls)"
	[ -z "$files" ] && return 0
	mkdir -p /tmp/.uci
	for file in $files; do
		( . "./$(basename $file)" ) && rm -f "$file"
	done
	uci commit
}

check_uci_config() {
	local factoryreset

	factoryreset=`fw_printenv factoryreset`
	[ -n "$factoryreset" -a ${factoryreset##*=} = "1" ] && {
		uci set profile.cloud.reset_flag='3'
		uci commit profile
		uci set CAPP.common.reset_flag='1'
		uci commit CAPP
		fw_setenv factoryreset 0
	}

	cd /etc/uci-checks || return 0
	files="$(ls)"
	[ -z "$files" ] && return 0
	for file in $files; do
		( . "./$(basename $file)" )
	done
}

setup_system_log() {

	echo "boot: setup system logging" > /dev/console

	/etc/init.d/syslog-ng disable
	# kernel message
	local conloglevel=`uci get system.@system[0].conloglevel`
	local buffersize=`uci get system.@system[0].buffersize`
	[ -z "$conloglevel" -a -z "$buffersize" ] || dmesg ${conloglevel:+-n $conloglevel} ${buffersize:+-s $buffersize}

	# klogd
	if [ -x /sbin/klogd ]; then
		local klogconloglevel=`uci get system.@system[0].klogconloglevel`
		local args="${klogconloglevel:+-c $klogconloglevel}"
		service_start /sbin/klogd $args
	fi
}

restart_conf_manager(){
	echo "boot: restart conf_manager" > /dev/console
	if [ "$(pidof conf_manager)" != "" ];then
		kill -9 $(pidof conf_manager)
	fi
	/usr/bin/conf_manager &
	#sleep 5
}


setup_wan_access_rules(){
	echo "boot: setup web & ssh access rule" > /dev/console

	#if [ "$(uci -c /mnt/data/config/ get mfg.system.wifi_support)" = "0" ] || [ "$(uci -c /mnt/data/config/ get mfg.system.edu_ver_flag)" = "1" ]; then

		index=0
		is_rule_exist=0
		is_firewall_rule=$(uci get firewall.@rule[$index] 2> /dev/null)

		while [ "$is_firewall_rule" != "" ]; do

			name=$(uci get firewall.@rule[$index].name 2> /dev/null)

			if [ "$name" == "Allow-SSH" ]; then
				is_rule_exist=1
			fi

			# advance to the next firewall rule
			index=$(expr $index + 1)
			is_firewall_rule=$(uci get firewall.@rule[$index] 2> /dev/null)
		done

		if [ $is_rule_exist -eq 0 ]; then
			uci add firewall rule
			uci set firewall.@rule[-1].name=Allow-SSH
			uci set firewall.@rule[-1].src=wan
			uci set firewall.@rule[-1].proto=tcp
			uci set firewall.@rule[-1].dest_port=22
			uci set firewall.@rule[-1].family=ipv4
			uci set firewall.@rule[-1].target=ACCEPT
			uci commit firewall

			uci add firewall rule
			uci set firewall.@rule[-1].name=Allow-Web
			uci set firewall.@rule[-1].src=wan
			uci set firewall.@rule[-1].proto=tcp
			uci set firewall.@rule[-1].dest_port=80
			uci set firewall.@rule[-1].family=ipv4
			uci set firewall.@rule[-1].target=ACCEPT
			uci commit firewall
		fi


	#fi

}

setup_hot_fix(){
	if [ -L /etc/rc.d/S22start_3g_service ]; then
		mv /etc/rc.d/S22start_3g_service /etc/rc.d/S15start_3g_service
	fi
	if [ -L /etc/rc.d/S95watchdog ]; then
		mv /etc/rc.d/S95watchdog /etc/rc.d/S11watchdog
	fi

	if [ -L /etc/rc.d/S50sshd ]; then
		mv /etc/rc.d/S50sshd /etc/rc.d/S98sshd
	fi

	if [ -L /etc/rc.d/S50uhttpd ]; then
                mv /etc/rc.d/S50uhttpd /etc/rc.d/S99uhttpd
        fi

	if [ -L /etc/rc.d/S95done ]; then
		mv /etc/rc.d/S95done /etc/rc.d/S99done
        fi
}

config_mt7620_mii () {
	echo "boot: config mt7620 mii" > /dev/console
	/usr/bin/mii_mgr -s -p 0 -r 0 -v 0x3300
	/usr/bin/mii_mgr -s -p 1 -r 0 -v 0x3300
	/usr/bin/mii_mgr -s -p 2 -r 0 -v 0x3900
	/usr/bin/mii_mgr -s -p 3 -r 0 -v 0x3900
	/usr/bin/mii_mgr -s -p 4 -r 0 -v 0x3100
}

setup_ether_hostname () {
	local base_mac=`uci -c /mnt/data/config/ get mfg.system.base_mac`
	local hasConfigured=`uci get system.@system[0].hasConfigured`
	local hasHostname=`uci get network.globals.hostname`

	echo "boot: setup ethernet MAC, hostname" > /dev/console

	if [ "$base_mac" != "unknown" ]; then
		ifconfig eth0 hw ether $base_mac
	else
		echo "boot: eth0 base mac is unknown" > /dev/console
	fi

	if [ -z "$hasConfigured" ]; then
		[ "$base_mac" != "unknown" ] && {
			# set hostname
			sepmac=`echo $base_mac | cut -f 4,5,6 -d ':' | sed 's/://g'`
			echo "boot: set hostname: MQC-${sepmac}" > /dev/console
			uci set system.@system[0].hostname="MQC-${sepmac}"
			uci commit system
		}
	fi

	if [ -z "$hasHostname" ]; then
		[ "$base_mac" != "unknown" ] && {
			sepmac=`echo $base_mac | cut -f 4,5,6 -d ':' | sed 's/://g'`
			uci set network.globals.hostname="MQC-${sepmac}"
			uci commit network

			local current_wan_type=`uci get network.wan.wantype`
			local current_wan_hostname=`uci get network.wan.hostname`

			if [ $current_wan_type == "dhcp" ]; then
				if [ -z $current_wan_hostname ]; then
					uci set network.wan.hostname="MQC-${sepmac}"
					uci commit network
				fi
			fi
		}
	fi
}

setup_root_ssh_login () {
	# Disable ssh root login
	local rootLoginOff=`uci get dropbear.@dropbear[0].RootLogin`
	if [ -z "$rootLoginOff" ]; then
		uci set dropbear.@dropbear[0].RootLogin="off"
		uci commit dropbear
	fi
}
setup_wifi_support(){
    uci -c /mnt/data/config/ set mfg.system.wifi_support="$1"
    uci -c /mnt/data/config/ commit
}
boot() {
	local isOverlayUsrCleared=`uci get system.@system[0].overlayUsrCleared`


	if [ "$isOverlayUsrCleared" != "1" ]; then
		echo "boot: /overlay/* cleaning" > /dev/console
		rm -rf /overlay/usr/bin/*
		rm -rf /overlay/app/lighttpd/www/ini/*
		rm -rf /overlay/app/prodtest/*
		uci set system.@system[0].overlayUsrCleared='1'
		uci commit system
	fi

	[ -f /proc/mounts ] || /sbin/mount_root
	[ -f /proc/jffs2_bbc ] && echo "S" > /proc/jffs2_bbc
	[ -f /proc/net/vlan/config ] && vconfig set_name_type DEV_PLUS_VID_NO_PAD

	config_mt7620_mii

	if cat /etc/crontabs/root | grep -q "process_monitor.sh" ; then
		echo "" >/tmp/temp_cront
		cp /tmp/temp_cront > /etc/crontabs/root
		/etc/init.d/cron restart

	fi

	local fstype=`fw_printenv fstype 2>/dev/null | awk -F '=' '{print $2}'`
	if [ "$fstype" = "ubifs" ]; then
		mount_data_ubifs
	else
		mount_data_jffs2
	fi

	setup_dirs_n_files
	setup_mfg_config
	setup_wan_access_rules
	setup_profile_config
	#setup_boot_firmware
	setup_system_log
	setup_ether_hostname
	setup_root_ssh_login
	setup_wifi_support 0

	/sbin/kmodloader >/dev/console 2>&1

	# allow wifi modules time to settle
	sleep 1
	/sbin/wifi detect > /tmp/wireless.tmp 2>/dev/console
	[ -s /tmp/wireless.tmp ] && {
		cat /tmp/wireless.tmp >> /etc/config/wireless
	}
	rm -f /tmp/wireless.tmp

	/sbin/provision.sh check

	/sbin/wifi checkssid
	/sbin/wifi setcountry
	/sbin/wifi setcountryregion

	setup_hot_fix
	
	uci_apply_defaults
	check_uci_config
	check_mfg
	# temporary hack until configd exists
	/sbin/reload_config

	start

	# create /dev/root if it doesn't exist
	[ -e /dev/root -o -h /dev/root ] || {
		rootdev=$(awk 'BEGIN { RS=" "; FS="="; } $1 == "root" { print $2 }' < /proc/cmdline)
		[ -n "$rootdev" ] && ln -s "$rootdev" /dev/root
	}

	# enable reset buttons
	btnd reset 69 &

	#Do boot sitesurvey
	rcConf reload wifiscan

	export export PATH="$PATH:/app/db"

	#Reset pin of LTE high
	/usr/bin/gpio l 29 0 4000 0 0 0

	#Power on LTE
	/usr/bin/gpio l 32 0 4000 0 0 0

	#LTE module need delay (around 15 s) to be detected before inserted driver in start_3g_service
	sleep 15

	#Init for LoRa
	#restart_conf_manager
	/lora_util/reset_gw.sh

}
