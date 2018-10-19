
#!/bin/sh

. /lib/functions/system.sh

ALIAS_IP="168.168.168.253"
DEF_GW="168.168.168.0"
WAN1_ETH_DEF_IP="0.0.0.0"
CHK_ALIAS_IP="/tmp/chk_alias_ip"
CHK_ROUTE="/tmp/chk_route"
WAN_IF="eth0.2"

echo "test"

chk_add_alias_ip_old(){
        /sbin/ifconfig > $CHK_ALIAS_IP
        #echo "[alias ip] set WAN_IF = ${WAN_IF}"
        if grep -q "$WAN_IF" "$CHK_ALIAS_IP" ; then
                /sbin/route -n > $CHK_ROUTE
                if ! ifconfig | grep -q "$WAN_IF:0" ; then
                        ifconfig $WAN_IF:0 $ALIAS_IP netmask 255.255.255.0
                        echo "[alias ip]: Add $WAN_IF:0 done."
                else
                        echo "[alias ip]: $WAN_IF:0 is already in interface list."
                fi
                if ! grep -q "$DEF_GW" "$CHK_ROUTE" ; then
                        return 0
                else
                        echo "[alias ip] $ALIAS_IP already in route table!" > /tmp/alias_ip_in_tb
                        return 0
                fi
        else
                echo "[alias ip] $WAN_IF is not found!" > /tmp/wan_not_found
                return 1
        fi

}

do_main_old(){

        if [[ "$1" = "34g" || "$1" = "apcli" ]]; then
                now_wan_proto=`uci get network.wan.proto`
                now_wan_type=`uci get network.wan.wantype`
                now_wan_static_ip=`uci get network.wan.ipaddr`
                if [[ "$now_wan_proto" = "static" && "$now_wan_type" = "static" && "$now_wan_static_ip" != "" ]] ; then
                        echo "Use WAN static IP!"
                else
                        #add wan1
                        #Target:
                        #config interface 'wan1'
                        #option ifname 'eth0.2'
                        #option proto 'static'
                        #option macaddr '00:0C:43:76:20:12'

                        lan_mac=`uci get profile.system.base_mac`
                        [ "$lan_mac" = "unknown" ] && lan_mac=$(cat /sys/class/net/eth0/address)
                        now_wan_mac=$(macaddr_add "$lan_mac" 1)

                        #echo "now_wan_mac=$now_wan_mac"
                        if grep -q "wan1" /etc/config/network ; then
                                uci delete network.wan1
                        fi

                        uci set network.wan1='interface'
                        uci set network.wan1.ifname=$WAN_IF
                        uci set network.wan1.ipaddr=$WAN1_ETH_DEF_IP
                        uci set network.wan1.netmask='255.255.255.0'
                        uci set network.wan1.proto='static'
                        uci set network.wan1.macaddr=$now_wan_mac

                        uci commit
                        ifup wan1

                fi
        else
                now_wan1_ifname=`uci get network.wan.ifname`
                if [ "$now_wan1_ifname" = "" ]; then
                        echo "WAN1 doesn't exist!"
                else
                        #remove wan1
                        uci delete network.wan1
                        uci commit
                fi
        fi

        chk_add_alias_ip
        if [ "$2" != "" ]; then
                sleep $2
        else
                sleep 3
        fi
        chk_add_alias_ip

}
do_main()
{
          #we don't need to create additional interface ALIAS
        }

 chk_add_alias_ip()
 {
        #we don't need to create additional interface ALIAS
 }       
chk_add_alias_ip
do_main $1 $2
rm -f $CHK_ALIAS_IP
rm -f $CHK_ROUTE
