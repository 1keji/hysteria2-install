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

# 检查是否以root用户运行
[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

# 获取操作系统信息
CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

# 如果未识别到操作系统，退出脚本
[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

# 检查curl是否安装，如果未安装则安装
if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

# 获取服务器的公网IP
realip(){
    ip=$(curl -s4m8 ip.gs -k) || ip=$(curl -s6m8 ip.gs -k)
}

# 证书安装函数
inst_cert(){
    green "Hysteria 2 协议证书安装方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 使用现有证书"
    echo -e " ${GREEN}3.${PLAIN} 手动输入证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        # 定义常见的证书存储路径，包括 Let's Encrypt 和 Nginx 的证书目录
        CERT_PATHS=(
            "/etc/letsencrypt/live/*/"          # Let's Encrypt 证书
            "/etc/nginx/ssl/*/"                  # Nginx 证书目录（根据实际情况调整）
            "/root/tls/*/"                       # 自定义证书目录
            "/etc/ssl/certs/"
            "/etc/pki/tls/certs/"
            "/usr/local/share/ca-certificates/"
            "/etc/hysteria/certs/"
        )

        declare -A cert_pairs
        index=1

        # 搜索匹配的证书和密钥文件对
        for path in "${CERT_PATHS[@]}"; do
            # 使用 glob 扩展匹配子目录
            for p in $path; do
                if [[ -d $p ]]; then
                    # 查找 fullchain.pem 和 privkey.pem
                    if [[ -f "${p}fullchain.pem" && -f "${p}privkey.pem" ]]; then
                        domain=$(basename "$p")
                        cert_pairs["$index,$p"]="fullchain.pem,privkey.pem,$domain"
                        index=$((index + 1))
                    fi
                    # 也可以添加对 cert.pem 和 privkey.pem 的支持
                    if [[ -f "${p}cert.pem" && -f "${p}privkey.pem" ]]; then
                        domain=$(basename "$p")
                        cert_pairs["$index,$p"]="cert.pem,privkey.pem,$domain"
                        index=$((index + 1))
                    fi
                fi
            done
        done

        if [[ ${#cert_pairs[@]} -eq 0 ]]; then
            red "未在常见路径中找到匹配的证书和密钥文件对。"
            exit 1
        fi

        green "找到以下证书和密钥文件对："
        for key in "${!cert_pairs[@]}"; do
            IFS=',' read -r num path <<< "$key"
            IFS=',' read -r crt_file key_file domain <<< "${cert_pairs[$key]}"
            echo -e " ${GREEN}$num.${PLAIN} 证书: $crt_file, 密钥: $key_file, 路径: $path"
        done

        while true; do
            read -rp "请输入要使用的证书编号: " selected
            selected_key=$(echo "${!cert_pairs[@]}" | tr ' ' '\n' | grep "^$selected,")
            if [[ -n $selected_key ]]; then
                IFS=',' read -r selected_num selected_path <<< "$selected_key"
                selected_pair=${cert_pairs[$selected_key]}
                IFS=',' read -r selected_crt selected_key_file selected_domain <<< "$selected_pair"
                cert_path="${selected_path}${selected_crt}"
                key_path="${selected_path}${selected_key_file}"
                hy_domain=$selected_domain
                break
            else
                red "无效的选择，请重新输入。"
            fi
        done

        green "已选择的证书路径："
        yellow "公钥文件: $cert_path"
        yellow "密钥文件: $key_path"
        yellow "证书域名: $hy_domain"

        chmod +rw "$cert_path"
        chmod +rw "$key_path"
    elif [[ $certInput == 3 ]]; then
        read -rp "请输入证书文件的绝对路径 (例如 /etc/letsencrypt/live/gz.566333.xyz/fullchain.pem): " cert_path
        read -rp "请输入密钥文件的绝对路径 (例如 /etc/letsencrypt/live/gz.566333.xyz/privkey.pem): " key_path
        read -rp "请输入证书域名: " domain
        hy_domain=$domain

        green "已输入的证书路径："
        yellow "公钥文件 cert 的路径：$cert_path"
        yellow "密钥文件 key 的路径：$key_path"
        yellow "证书域名：$domain"

        # 验证文件是否存在
        if [[ ! -f "$cert_path" || ! -f "$key_path" ]]; then
            red "证书文件或密钥文件不存在，请检查路径并重试。"
            exit 1
        fi

        chmod +rw "$cert_path"
        chmod +rw "$key_path"
    else
        green "将使用自签证书作为 Hysteria 2 的节点证书"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out "$key_path"
        openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" -subj "/CN=www.bing.com"
        chmod 600 "$cert_path"
        chmod 600 "$key_path"
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

# 设置 Hysteria 2 端口
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

# 设置端口使用模式
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
        iptables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
        ip6tables -t nat -A PREROUTING -p udp --dport "$firstport":"$endport" -j REDIRECT --to-ports "$port"
        netfilter-persistent save >/dev/null 2>&1
    else
        red "将继续使用单端口模式"
    fi
}

# 设置 Hysteria 2 密码
inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为16位以上的随机字符）：" auth_pwd
    if [[ -z $auth_pwd ]]; then
        # 生成至少16位的随机字母数字密码
        auth_pwd=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
        echo
    fi
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

# 设置 Hysteria 2 伪装网站
inst_site(){
    read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [maimai.sega.jp]：" proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "使用在 Hysteria 2 节点的伪装网站为：$proxysite"
}

# 安装 Hysteria 2
insthysteria(){
    realip

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
    if [[ -n $firstport && -n $endport ]]; then
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
  - name: Hysteria2
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
      - Hysteria2

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF

    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Hysteria2"
    echo "$url" > /root/hy/url.txt
    nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain#Hysteria2"
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
    yellow "Hysteria 2 客户端 YAML 配置文件已保存到 /root/hy/hy-client.yaml，内容如下："
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件已保存到 /root/hy/hy-client.json，内容如下："
    red "$(cat /root/hy/hy-client.json)"
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 2 节点分享链接已保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 节点单端口的分享链接已保存到 /root/hy/url-nohop.txt"
    red "$(cat /root/hy/url-nohop.txt)"
}

# 卸载 Hysteria 2
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

# 启动 Hysteria 2
starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

# 关闭 Hysteria 2
stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

# 重启 Hysteria 2
hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [1-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

# 修改 Hysteria 2 端口
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

# 修改 Hysteria 2 密码
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

# 修改 Hysteria 2 证书
change_cert(){
    old_cert=$(grep '^tls:' /etc/hysteria/config.yaml -A2 | grep '^  cert:' | awk '{print $2}')
    old_key=$(grep '^tls:' /etc/hysteria/config.yaml -A2 | grep '^  key:' | awk '{print $2}')
    old_hydomain=$(grep '^sni:' /root/hy/hy-client.yaml | awk '{print $2}')

    green "搜索常见的 TLS 证书路径，包括 Let's Encrypt 和 Nginx 的证书目录..."
    CERT_PATHS=(
        "/etc/letsencrypt/live/*/"          # Let's Encrypt 证书
        "/etc/nginx/ssl/*/"                  # Nginx 证书目录（根据实际情况调整）
        "/root/tls/*/"                       # 自定义证书目录
        "/etc/ssl/certs/"
        "/etc/pki/tls/certs/"
        "/usr/local/share/ca-certificates/"
        "/etc/hysteria/certs/"
    )

    declare -A cert_pairs
    index=1

    # 搜索匹配的证书和密钥文件对
    for path in "${CERT_PATHS[@]}"; do
        # 使用 glob 扩展匹配子目录
        for p in $path; do
            if [[ -d $p ]]; then
                # 查找 fullchain.pem 和 privkey.pem
                if [[ -f "${p}fullchain.pem" && -f "${p}privkey.pem" ]]; then
                    domain=$(basename "$p")
                    cert_pairs["$index,$p"]="fullchain.pem,privkey.pem,$domain"
                    index=$((index + 1))
                fi
                # 也可以添加对 cert.pem 和 privkey.pem 的支持
                if [[ -f "${p}cert.pem" && -f "${p}privkey.pem" ]]; then
                    domain=$(basename "$p")
                    cert_pairs["$index,$p"]="cert.pem,privkey.pem,$domain"
                    index=$((index + 1))
                fi
            fi
        done
    done

    if [[ ${#cert_pairs[@]} -eq 0 ]]; then
        red "未在常见路径中找到匹配的证书和密钥文件对。"
        exit 1
    fi

    green "找到以下证书和密钥文件对："
    for key in "${!cert_pairs[@]}"; do
        IFS=',' read -r num path <<< "$key"
        IFS=',' read -r crt_file key_file domain <<< "${cert_pairs[$key]}"
        echo -e " ${GREEN}$num.${PLAIN} 证书: $crt_file, 密钥: $key_file, 路径: $path"
    done

    while true; do
        read -rp "请输入要使用的证书编号: " selected
        selected_key=$(echo "${!cert_pairs[@]}" | tr ' ' '\n' | grep "^$selected,")
        if [[ -n $selected_key ]]; then
            IFS=',' read -r selected_num selected_path <<< "$selected_key"
            selected_pair=${cert_pairs[$selected_key]}
            IFS=',' read -r selected_crt selected_key_file selected_domain <<< "$selected_pair"
            new_cert_path="${selected_path}${selected_crt}"
            new_key_path="${selected_path}${selected_key_file}"
            new_domain=$selected_domain
            break
        else
            red "无效的选择，请重新输入。"
        fi
    done

    sed -i "s#$old_cert#$new_cert_path#g" /etc/hysteria/config.yaml
    sed -i "s#$old_key#$new_key_path#g" /etc/hysteria/config.yaml
    sed -i "s/$old_hydomain/$new_domain/g" /root/hy/hy-client.yaml
    sed -i "s/$old_hydomain/$new_domain/g" /root/hy/hy-client.json

    hy_domain=$new_domain
    cert_path=$new_cert_path
    key_path=$new_key_path

    chmod +rw "$cert_path"
    chmod +rw "$key_path"

    stophysteria && starthysteria

    green "Hysteria 2 节点证书已成功修改为：$cert_path 和 $key_path"
    yellow "请手动更新客户端配置文件以使用节点"
    showconf
}

# 修改 Hysteria 2 伪装网站
changeproxysite(){
    oldproxysite=$(grep '^masquerade:' /etc/hysteria/config.yaml | grep 'url:' | awk -F "https://" '{print $2}' | awk '{print $1}')

    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "Hysteria 2 节点伪装网站已成功修改为：$proxysite"
}

# 修改 Hysteria 2 配置
changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书"
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

# 显示 Hysteria 2 配置
showconf(){
    yellow "Hysteria 2 客户端 YAML 配置文件已保存到 /root/hy/hy-client.yaml，内容如下："
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件已保存到 /root/hy/hy-client.json，内容如下："
    red "$(cat /root/hy/hy-client.json)"
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 2 节点分享链接已保存到 /root/hy/url.txt"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 节点单端口的分享链接已保存到 /root/hy/url-nohop.txt"
    red "$(cat /root/hy/url-nohop.txt)"
}

# 更新 Hysteria 2 内核
update_core(){
    wget -N https://raw.githubusercontent.com/1keji/hysteria2-install/main/install_server.sh
    bash install_server.sh

    rm -f install_server.sh
}

# 菜单函数
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
        0 ) exit 0 ;;
        * ) exit 1 ;;
    esac
}

# 运行菜单
menu
