#!/bin/bash

#######################################
# Script de Firewall
# Criado por: Thiago Nogueira
# Data de criação: 25/03/15
# Última modificação: 18/05/15
#######################################

### Variáveis ###
#INT="eth0"
EXT="ppp0"
#SUBNET="192.168.100.0/24"

################
# Função Help
################
function help(){
	echo -e "Para ativar o Firewall, adicione o parâmetro '--start'."
	echo -e "Para desativar, adicione '--stop'."
	echo -e "Para reiniciar, '--restart'."
	echo -e "Para obter ajuda, novamente, adicione o parâmetro '--help'."
}

################
# Função Stop
################
function stop(){
	### Exclui todas as regras ###
	iptables -F
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t filter -F

	### Exclui cadeias customizadas ###
	iptables -X

	### Zera os contadores das cadeias ###
	iptables -t nat -Z
	iptables -t mangle -Z
	iptables -t filter -Z

	### Carrega os modulos ###
	modprobe iptable_nat
	modprobe iptable_filter
	modprobe iptable_mangle

	### Políticas em ACCEPT ###
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
	# Ip6tables #
	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT

	## Habilita roteamento ###
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -o $EXT -j MASQUERADE
}	

################
# Função Start
################
function start(){
	### Exclui todas as regras ###
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t filter -F 

	### Exclui cadeias customizadas ###
	iptables -X 

	### Zera os contadores das cadeias ###
	iptables -t nat -Z 
	iptables -t mangle -Z 
	iptables -t filter -Z 

	### Carrega os modulos ###
	modprobe iptable_nat
	modprobe iptable_filter
	modprobe iptable_mangle 

	### Define a política padrão do firewall ###
	iptables -P INPUT DROP
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD DROP
	# Ip6tables #
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP	

	### Liberando DNS ###
	iptables -A FORWARD -p udp --dport 53 -j ACCEPT
	iptables -A FORWARD -p tcp --dport 53 -j ACCEPT
	iptables -A INPUT -p udp --dport 53 -j ACCEPT
	iptables -A INPUT -p tcp --dport 53 -j ACCEPT

	### Jogando tráfego da porta 80 e 443 para o Squid ###
	iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128 
	iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3130

	### Regras INPUT ###
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
	iptables -A INPUT -m state --state NEW -i !$EXT -j ACCEPT
	# Loopback #
	iptables -A INPUT -i lo -j ACCEPT 
	# ICMP 0 #
	iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT 
	# ICMP 8 #
	iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT 
	# SSH #
	iptables -A INPUT -p tcp --dport 22 -j ACCEPT 
	# FTP #
	iptables -A INPUT -p tcp --dport 21 -j ACCEPT 
	# OpenVPN #
	iptables -A INPUT -p tcp --dport 1194 -j ACCEPT 
	# HTTP #
	iptables -A INPUT -p tcp --dport 80 -j ACCEPT
	# SAMBA #
	iptables -A INPUT -p tcp --dport 139 -j ACCEPT
	iptables -A INPUT -p udp --dport 139 -j ACCEPT
	# VOIP #
	iptables -A INPUT -p udp --dport 5060 -j ACCEPT	
 
	### Regras FORWARD ###
	iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A FORWARD -m state --state NEW -i !$EXT -j ACCEPT
	# ICMP #
	iptables -A FORWARD -p icmp -j ACCEPT
	# SMTP #
	iptables -A FORWARD -p tcp --dport 25 -j ACCEPT 
	iptables -A FORWARD -p tcp --dport 587 -j ACCEPT
	iptables -A FORWARD -p tcp --dport 465 -j ACCEPT
	# IMAP #
	iptables -A FORWARD -p tcp --dport 993 -j ACCEPT
	# POP3 #
	iptables -A FORWARD -p tcp --dport 995 -j ACCEPT
        # POP #
        iptables -A FORWARD -p tcp --dport 110 -j ACCEPT
	# SSH #
	iptables -A FORWARD -p tcp --dport 22 -j ACCEPT 
	# FTP #
	iptables -A FORWARD -p tcp --dport 20 -j ACCEPT
	iptables -A FORWARD -p tcp --dport 21 -j ACCEPT 
	# POP #
	iptables -A FORWARD -p tcp --dport 110 -j ACCEPT
	# MS Terminal Server #
	iptables -A FORWARD -p tcp --dport 3389 -j ACCEPT
	# HTTP #
	iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
	# HTTPS #
	iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
	# VNC #
	iptables -A FORWARD -p tcp --dport 5900 -j ACCEPT 
        # SAMBA #
        iptables -A FORWARD -p tcp --dport 139 -j ACCEPT
        iptables -A FORWARD -p udp --dport 139 -j ACCEPT
	# VOIP #
	iptables -A FORWARD -p udp --sport 5060 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
	iptables -A FORWARD -p udp --dport 5060 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A FORWARD -p udp --sport 10000:20000 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
	iptables -A FORWARD -p udp --dport 10000:20000 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	# Sites #
	for list in `cat /etc/firewall/sites_bloq` ; do
		iptables -I FORWARD -m string --algo bm --string $list -j DROP
	done

	### Regras OUTPUT ###
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -m state --state NEW -o !$EXT -j ACCEPT 

	### Regras POSTROUTING ###
	route add default gw 192.168.100.1 2> /dev/null
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -o $EXT -j MASQUERADE 
}

case $1 in
	"")
		start
		echo -e "Firewall ativado\nPara ajuda, adicione o parâmetro '--help'"
		;;
	--start)
		start
		echo -e "Firewall ativado\nPara ajuda, adicione o parâmetro '--help'"
		;;
	--stop)
		stop
		echo -e "Firewall desativado\nPara ajuda, adicione o parâmetro '--help'"		
		;;
	--restart)
		stop
		start
		echo -e "Firewall reiniciado\nPara ajuda, adicione o parâmetro '--help'"
		;;
	--help)
		help
		;;
	*)
		echo -e "Parâmetro inválido\nPara ajuda, adicione o parâmetro '--help'"
		exit 0
		;;
esac
