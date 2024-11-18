#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
    [[ $? -ne 0 ]] && red "安装curl失败，请手动安装后重试。" && exit 1
fi

realip(){
    ip=$(curl -s4m8 ip.gs -k) || ip=$(curl -s6m8 ip.gs -k)
    [[ -z $ip ]] && red "无法获取服务器IP，请检查网络连接。" && exit 1
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        # 只设置必要的权限
        chmod 700 /root
        touch /root/cert.crt /root/private.key /root/ca.log
        chmod 600 /root/cert.crt /root/private.key /root/ca.log

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi

            read -rp "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
            domainIP=$(dig @8.8.8.8 +time=2 +short "$domain" 2>/dev/null)
            if echo "$domainIP" | grep -q "network unreachable\|timed out" || [[ -z $domainIP ]]; then
                domainIP=$(dig @2001:4860:4860::8888 +time=2 aaaa +short "$domain" 2>/dev/null)
            fi
            if echo "$domainIP" | grep -q "network unreachable\|timed out" || [[ -z $domainIP ]]; then
                red "未解析出 IP，请检查域名是否输入有误" 
                yellow "是否尝试强行匹配？"
                green "1. 是，将使用强行匹配"
                green "2. 否，退出脚本"
                read -rp "请输入选项 [1-2]：" ipChoice
                if [[ $ipChoice == 1 ]]; then
                    yellow "将尝试强行匹配以申请域名证书"
                else
                    red "将退出脚本"
                    exit 1
                fi
            fi
            # 修改这里的IP比对逻辑，允许多个IP匹配
            if echo "$domainIP" | grep -qw "$ip"; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                [[ $? -ne 0 ]] && red "安装依赖失败，请手动安装后重试。" && exit 1
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    [[ $? -ne 0 ]] && red "安装cronie失败，请手动安装后重试。" && exit 1
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    [[ $? -ne 0 ]] && red "安装cron失败，请手动安装后重试。" && exit 1
                    systemctl start cron
                    systemctl enable cron
                fi
                green "请输入一个有效的邮箱地址，用于申请证书："
                read -rp "邮箱: " acme_email
                while [[ -z "$acme_email" ]]; do
                    red "邮箱地址不能为空，请重新输入。"
                    read -rp "邮箱: " acme_email
                done

                green "正在安装 Acme.sh..."
                curl https://get.acme.sh | sh -s email="$acme_email"
                [[ $? -ne 0 ]] && red "Acme.sh 安装失败，请检查网络或手动安装后重试。" && exit 1
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                [[ $? -ne 0 ]] && red "Acme.sh 配置失败，请检查安装过程。" && exit 1

                if [[ -n $(echo "$ip" | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --insecure
                fi
                [[ $? -ne 0 ]] && red "证书申请失败，请检查域名解析或其他问题。" && exit 1

                bash ~/.acme.sh/acme.sh --install-cert -d "${domain}" --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                [[ $? -ne 0 ]] && red "证书安装失败，请检查 Acme.sh 输出日志。" && exit 1

                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo "$domain" > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    yellow "证书crt文件路径如下: /root/cert.crt"
                    yellow "私钥key文件路径如下: /root/private.key"
                    hy_domain="$domain"
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 脚本可能跟不上时代, 建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -rp "请输入公钥文件 crt 的路径：" cert_path
        [[ -z $cert_path ]] && red "公钥文件路径不能为空！" && exit 1
        yellow "公钥文件 crt 的路径：$cert_path "
        read -rp "请输入密钥文件 key 的路径：" key_path
        [[ -z $key_path ]] && red "密钥文件路径不能为空！" && exit 1
        yellow "密钥文件 key 的路径：$key_path "
        read -rp "请输入证书的域名：" domain
        [[ -z $domain ]] && red "域名不能为空！" && exit 1
        yellow "证书域名：$domain"
        hy_domain="$domain"

        chmod +rw "$cert_path" "$key_path"
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        mkdir -p /etc/hysteria
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        chmod 600 /etc/hysteria/cert.crt
        chmod 600 /etc/hysteria/private.key
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -rp "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -rp "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "将在 Hysteria 2 节点使用的端口是：$port"
    inst_jump
}

inst_jump(){
    green "Hysteria 2 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -rp "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -rp "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "你设置的起始端口必须小于末尾端口，请重新输入起始和末尾端口"
                    read -rp "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                    read -rp "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                fi
            done
        fi
        # 使用 REDIRECT 而非 DNAT 以实现端口跳跃
        iptables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
        ip6tables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
        netfilter-persistent save >/dev/null 2>&1
    else
        red "将继续使用单端口模式"
    fi
}

inst_pwd(){
    read -rp "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [maimai.sega.jp]：" proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent
    [[ $? -ne 0 ]] && red "安装基础软件包失败，请手动安装后重试。" && exit 1

    wget -N https://raw.githubusercontent.com/1keji/hysteria2-install/main/install_server.sh
    [[ $? -ne 0 ]] && red "下载 install_server.sh 失败，请检查网络。" && exit 1
    bash install_server.sh
    [[ $? -ne 0 ]] && red "运行 install_server.sh 失败，请检查。" && exit 1
    rm -f install_server.sh

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 2 安装成功！"
    else
        red "Hysteria 2 安装失败！"
        exit 1
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_port
    inst_pwd
    inst_site

    # 设置 Hysteria 配置文件
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    # 确定最终入站端口范围
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    if [[ -n $(echo "$ip" | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    mkdir -p /root/hy
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$last_port

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:7887  # 修改此处端口号为您想要的端口，例如7887

transport:
  udp:
    hopInterval: 30s 
EOF
    cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$last_port",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "fastOpen": true,
  "socks5": {
    "listen": "127.0.0.1:7887"  # 修改此处端口号为您想要的端口，例如7887
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF
    cat <<EOF > /root/hy/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114
proxies:
  - name: 1keji-Hysteria2
    type: hysteria2
    server: $last_ip
    port: $port
    password: $auth_pwd
    sni: $hy_domain
    skip-cert-verify: true
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - 1keji-Hysteria2
      
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#1keji-Hysteria2"
    echo "$url" > /root/hy/url.txt
    nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain#1keji-Hysteria2"
    echo "$nohopurl" > /root/hy/url-nohop.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出" && exit 1
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 节点单端口的分享链接如下，并保存到 /root/hy/url-nohop.txt"
    red "$(cat /root/hy/url-nohop.txt)"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(grep '^listen:' /etc/hysteria/config.yaml | awk '{print $2}' | awk -F ":" '{print $2}')

    read -rp "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -rp "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "s/^listen: :$oldport/listen: :$port/g" /etc/hysteria/config.yaml
    sed -i "s/:$oldport$/:$port/g" /root/hy/hy-client.yaml
    sed -i "s/\"$oldport\"/\"$port\"/g" /root/hy/hy-client.json

    # 更新 iptables 规则
    iptables -t nat -D PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$oldport" >/dev/null 2>&1
    ip6tables -t nat -D PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$oldport" >/dev/null 2>&1

    if [[ -n $firstport ]]; then
        iptables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
        ip6tables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
    fi

    netfilter-persistent save >/dev/null 2>&1

    stophysteria && starthysteria

    green "Hysteria 2 端口已成功修改为：$port"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changepasswd(){
    oldpasswd=$(grep '^password:' /etc/hysteria/config.yaml | awk '{print $2}')

    read -rp "设置 Hysteria 2 密码（回车跳过为随机字符）：" passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "s/^password: $oldpasswd/password: $passwd/g" /etc/hysteria/config.yaml
    sed -i "s/auth: $oldpasswd/auth: $passwd/g" /root/hy/hy-client.yaml
    sed -i "s/\"$oldpasswd\"/\"$passwd\"/g" /root/hy/hy-client.json

    stophysteria && starthysteria

    green "Hysteria 2 节点密码已成功修改为：$passwd"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

change_cert(){
    old_cert=$(grep '^cert:' /etc/hysteria/config.yaml | awk '{print $2}')
    old_key=$(grep '^key:' /etc/hysteria/config.yaml | awk '{print $2}')
    old_hydomain=$(grep '^sni:' /root/hy/hy-client.yaml | awk '{print $2}')

    inst_cert

    sed -i "s#$old_cert#$cert_path#g" /etc/hysteria/config.yaml
    sed -i "s#$old_key#$key_path#g" /etc/hysteria/config.yaml
    sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml
    sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.json

    stophysteria && starthysteria

    green "Hysteria 2 节点证书类型已成功修改"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changeproxysite(){
    oldproxysite=$(grep '^url:' /etc/hysteria/config.yaml | awk -F "https://" '{print $2}')

    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
}

changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书类型"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装网站"
    echo ""
    read -rp " 请选择操作 [1-4]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下，并保存到 /root/hy/hy-client.yaml"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 2 节点分享链接如下，并保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 节点单端口的分享链接如下，并保存到 /root/hy/url-nohop.txt"
    red "$(cat /root/hy/url-nohop.txt)"
}

update_core(){
    wget -N https://raw.githubusercontent.com/1keji/hysteria2-install/main/install_server.sh
    [[ $? -ne 0 ]] && red "下载 install_server.sh 失败，请检查网络。" && exit 1
    bash install_server.sh
    [[ $? -ne 0 ]] && red "运行 install_server.sh 失败，请检查。" && exit 1
    rm -f install_server.sh
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${RED}Hysteria 2 一键安装脚本${PLAIN}                   #"
    echo -e "# ${GREEN}作者${PLAIN}: 1keji                                             #"
    echo -e "# ${GREEN}博客${PLAIN}: https://1keji.net                                 #"
    echo -e "# ${GREEN}GitHub 项目${PLAIN}: https://github.com/1keji/hysteria2-install #"
    echo "##############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} 关闭、开启、重启 Hysteria 2"
    echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 2 配置"
    echo -e " ${GREEN}5.${PLAIN} 显示 Hysteria 2 配置文件"
    echo " -------------"
    echo -e " ${GREEN}6.${PLAIN} 更新 Hysteria 2 内核"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -rp "请输入选项 [0-6]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) update_core ;;
        0 ) exit 0 ;;
        * ) red "无效的选项，退出脚本。" && exit 1 ;;
    esac
}

menu
