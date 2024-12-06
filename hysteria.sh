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

# 确保安装 curl
if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

# 确保安装 dig
install_dig(){
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        ${PACKAGE_INSTALL[int]} dnsutils
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        ${PACKAGE_INSTALL[int]} bind-utils
    else
        red "无法自动安装 dig，请手动安装。"
        exit 1
    fi
}

if [[ -z $(type -P dig) ]]; then
    green "dig 未安装，正在安装 dig 工具..."
    install_dig
fi

# 确保安装 net-tools 用于 ss 命令
if [[ -z $(type -P ss) ]]; then
    green "ss 未安装，正在安装 net-tools 工具..."
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        ${PACKAGE_INSTALL[int]} net-tools
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        ${PACKAGE_INSTALL[int]} net-tools
    fi
fi

realip(){
    # 获取所有服务器的IP地址，包括IPv4和IPv6
    ipv4=$(curl -s4m8 ip.gs -k) || ipv4=""
    ipv6=$(curl -s6m8 ip.gs -k) || ipv6=""
    server_ips=()
    if [[ -n $ipv4 ]]; then
        server_ips+=("$ipv4")
    fi
    if [[ -n $ipv6 ]]; then
        server_ips+=("$ipv6")
    fi
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 使用 Certbot 自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod -R 700 /root

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
        else
            # 检查并安装 Certbot
            if [[ -z $(type -P certbot) ]]; then
                green "Certbot 未安装，正在安装 Certbot..."
                if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
                    ${PACKAGE_UPDATE[int]}
                    ${PACKAGE_INSTALL[int]} certbot
                elif [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} epel-release
                    ${PACKAGE_UPDATE[int]}
                    ${PACKAGE_INSTALL[int]} certbot
                elif [[ $SYSTEM == "Fedora" ]]; then
                    ${PACKAGE_UPDATE[int]}
                    ${PACKAGE_INSTALL[int]} certbot
                else
                    red "不支持的操作系统，请手动安装 Certbot。"
                    exit 1
                fi
            fi

            # 获取服务器IP
            realip

            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1

            # 检查域名解析是否正确
            domainIP=$(dig @8.8.8.8 +time=2 +short "$domain" A 2>/dev/null)
            domainIPv6=$(dig @2001:4860:4860::8888 +time=2 +short "$domain" AAAA 2>/dev/null)
            if [[ -z $domainIP && -z $domainIPv6 ]]; then
                red "未解析出 IP，请检查域名是否输入有误或 DNS 设置是否正确。"
                exit 1
            fi

            # 确保域名指向服务器的某个IP
            ip_match=0
            for server_ip in "${server_ips[@]}"; do
                if [[ "$domainIP" == "$server_ip" || "$domainIPv6" == "$server_ip" ]]; then
                    ip_match=1
                    break
                fi
            done

            if [[ $ip_match -ne 1 ]]; then
                yellow "域名解析的IP与当前VPS的IP不完全匹配，请确认。"
                read -rp "是否继续申请证书？ [y/N]: " confirm
                if [[ ! $confirm =~ ^[Yy]$ ]]; then
                    red "取消证书申请。"
                    exit 1
                fi
            fi

            # 停止 Hysteria 服务以释放端口
            systemctl stop hysteria-server >/dev/null 2>&1

            # 使用 Certbot 申请证书
            green "正在使用 Certbot 申请证书..."
            certbot certonly --standalone -d "$domain" --non-interactive --agree-tos -m "admin@$domain"

            if [[ $? -ne 0 ]]; then
                red "Certbot 申请证书失败，请检查域名和网络连接。"
                # 重启 Hysteria 服务
                systemctl start hysteria-server >/dev/null 2>&1
                exit 1
            fi

            # 复制证书到指定路径
            cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$cert_path"
            cp "/etc/letsencrypt/live/$domain/privkey.pem" "$key_path"

            # 设置权限
            chmod 600 "$cert_path" "$key_path"

            # 启动 Hysteria 服务
            systemctl start hysteria-server >/dev/null 2>&1

            # 保存域名到 ca.log
            echo "$domain" > /root/ca.log

            # 设置 Certbot 自动续期钩子
            green "正在设置 Certbot 自动续期钩子..."
            mkdir -p /etc/letsencrypt/renewal-hooks/post
            cat << EOF > /etc/letsencrypt/renewal-hooks/post/hysteria-renew.sh
#!/bin/bash
cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$cert_path"
cp "/etc/letsencrypt/live/$domain/privkey.pem" "$key_path"
systemctl reload hysteria-server
EOF
            chmod +x /etc/letsencrypt/renewal-hooks/post/hysteria-renew.sh

            green "证书申请成功！证书文件已保存到 /root 文件夹下。"
            yellow "证书crt文件路径如下: /root/cert.crt"
            yellow "私钥key文件路径如下: /root/private.key"
            hy_domain=$domain
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        yellow "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_domain=$domain

        chmod 600 "$cert_path"
        chmod 600 "$key_path"
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

    read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
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
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "你设置的起始端口必须小于末尾端口，请重新输入。"
                    read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                    read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                fi
            done
        fi
        # 使用 REDIRECT 而非 DNAT 以实现端口跳跃
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "将继续使用单端口模式"
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为16位以上的随机字符）：" auth_pwd
    if [[ -z $auth_pwd ]]; then
        # 生成至少16位的随机字母数字密码
        auth_pwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
        echo
    fi
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [回车maimai.sega.jp]：" proxysite
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

    # 新增代码：为 $ip 赋值
    if [[ -n $ipv4 ]]; then
        ip=$ipv4
    elif [[ -n $ipv6 ]]; then
        ip=$ipv6
    else
        red "无法获取服务器 IP 地址，请检查网络配置。"
        exit 1
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    wget -N https://raw.githubusercontent.com/1keji/hysteria2-install/main/install_server.sh
    bash install_server.sh
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
    if [[ -n $(echo $ip | grep ":") ]]; then
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
    "listen": "127.0.0.1:7887"
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
    echo $url > /root/hy/url.txt
    nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain#1keji-Hysteria2"
    echo $nohopurl > /root/hy/url-nohop.txt

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
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
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

    read -p "设置 Hysteria 2 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 2 端口 [1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "s/^listen: :$oldport/listen: :$port/g" /etc/hysteria/config.yaml
    sed -i "s/:$oldport$/:$port/g" /root/hy/hy-client.yaml
    sed -i "s/\"$oldport\"/\"$port\"/g" /root/hy/hy-client.json

    # 更新 iptables 规则
    if [[ -n $firstport && -n $endport ]]; then
        iptables -t nat -D PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $oldport >/dev/null 2>&1
        ip6tables -t nat -D PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $oldport >/dev/null 2>&1
    fi

    if [[ -n $firstport && -n $endport ]]; then
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j REDIRECT --to-ports $port
    fi

    netfilter-persistent save >/dev/null 2>&1

    stophysteria && starthysteria

    green "Hysteria 2 端口已成功修改为：$port"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

changepasswd(){
    oldpasswd=$(grep '^password:' /etc/hysteria/config.yaml | awk '{print $2}')

    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" passwd
    if [[ -z $passwd ]]; then
        # 生成至少16位的随机字母数字密码
        passwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
        echo
    fi

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
    oldproxysite=$(grep '^proxy:' /etc/hysteria/config.yaml | grep 'url:' | awk -F "https://" '{print $2}')

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
    read -p " 请选择操作 [1-4]：" confAnswer
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
    bash install_server.sh
    
    rm -f install_server.sh
}

menu() {
    clear
    echo "##############################################################"
    echo -e "#                  ${RED}Hysteria 2 一键安装脚本${PLAIN}                   #"
    echo -e "# ${GREEN}作者${PLAIN}: 1keji                                                #"
    echo -e "# ${GREEN}博客${PLAIN}: https://1keji.net                                    #"
    echo -e "# ${GREEN}GitHub 项目${PLAIN}: https://github.com/1keji/hysteria2-install    #"
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
        * ) exit 1 ;;
    esac
}

menu

