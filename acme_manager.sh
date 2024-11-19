#!/bin/bash

# acme_manager.sh - 一键安装和管理 acme.sh 脚本
# 适用于多种 Linux 发行版和 macOS

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否以 root 权限运行
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}请以 root 用户或使用 sudo 运行此脚本.${NC}"
        exit 1
    fi
}

# 检测操作系统和包管理器
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif [ "$(uname)" == "Darwin" ]; then
        OS="macos"
    else
        OS="unknown"
    fi

    case "$OS" in
        ubuntu|debian)
            PM="apt"
            ;;
        centos|fedora|rhel)
            PM="yum"
            ;;
        arch)
            PM="pacman"
            ;;
        macos)
            PM="brew"
            ;;
        *)
            PM="unknown"
            ;;
    esac
}

# 安装依赖
install_dependencies() {
    echo -e "${GREEN}正在检查并安装必要的依赖...${NC}"
    case "$PM" in
        apt)
            apt update
            apt install -y curl socat cron
            ;;
        yum)
            yum install -y epel-release
            yum install -y curl socat cronie
            ;;
        pacman)
            pacman -Sy --noconfirm curl socat cronie
            ;;
        brew)
            brew install curl socat
            # macOS 默认已安装 cron，通常不需要额外安装
            ;;
        *)
            echo -e "${RED}不支持的操作系统或包管理器: $OS${NC}"
            exit 1
            ;;
    esac

    # 启动并启用 cron 服务
    if [[ "$PM" == "apt" || "$PM" == "yum" || "$PM" == "pacman" ]]; then
        systemctl enable cron || systemctl enable crond
        systemctl start cron || systemctl start crond
        if systemctl is-active --quiet cron || systemctl is-active --quiet crond; then
            echo -e "${GREEN}cron 服务已启动并启用.${NC}"
        else
            echo -e "${RED}无法启动 cron 服务.${NC}"
            exit 1
        fi
    fi
}

# 安装 acme.sh
install_acme() {
    echo -e "${GREEN}正在安装 acme.sh...${NC}"
    if command -v acme.sh >/dev/null 2>&1; then
        echo -e "${GREEN}acme.sh 已经安装.${NC}"
    else
        curl https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo -e "${RED}acme.sh 安装失败.${NC}"
            exit 1
        fi
        # 获取 acme.sh 的绝对路径
        if [ -f "$HOME/.acme.sh/acme.sh" ]; then
            ACME_SH="$HOME/.acme.sh/acme.sh"
        elif [ -f "/root/.acme.sh/acme.sh" ]; then
            ACME_SH="/root/.acme.sh/acme.sh"
        else
            echo -e "${RED}无法找到 acme.sh 安装路径.${NC}"
            exit 1
        fi
        echo -e "${GREEN}acme.sh 安装成功. 路径: $ACME_SH${NC}"

        # 确保 acme.sh 添加到 PATH
        export PATH="$PATH:$HOME/.acme.sh"
        echo 'export PATH="$PATH:$HOME/.acme.sh"' >> ~/.bashrc
        source ~/.bashrc
    fi
}

# 获取 acme.sh 的路径
get_acme_path() {
    if [ -z "$ACME_SH" ]; then
        if command -v acme.sh >/dev/null 2>&1; then
            ACME_SH=$(command -v acme.sh)
        elif [ -f "$HOME/.acme.sh/acme.sh" ]; then
            ACME_SH="$HOME/.acme.sh/acme.sh"
        elif [ -f "/root/.acme.sh/acme.sh" ]; then
            ACME_SH="/root/.acme.sh/acme.sh"
        else
            echo -e "${RED}无法找到 acme.sh，请先安装.${NC}"
            exit 1
        fi
    fi
}

# 注册账户（如果尚未注册）
register_account() {
    get_acme_path
    echo -e "${GREEN}正在检查账户注册状态...${NC}"
    
    # 尝试列出账户信息，检查是否已注册
    ACCOUNT_INFO=$($ACME_SH --list 2>/dev/null)
    if echo "$ACCOUNT_INFO" | grep -q "Account Register Email"; then
        echo -e "${GREEN}账户已经注册.${NC}"
    else
        echo -e "${GREEN}请注册 acme.sh 账户以使用 ZeroSSL 或 Let's Encrypt CA.${NC}"
        while true; do
            read -p "请输入您的电子邮件地址 (用于注册 acme.sh 账户): " USER_EMAIL
            if [[ "$USER_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                break
            else
                echo -e "${RED}无效的电子邮件地址，请重新输入.${NC}"
            fi
        done
        echo -e "${GREEN}正在注册账户...${NC}"
        $ACME_SH --register-account -m "$USER_EMAIL" --server zerossl
        if [ $? -ne 0 ]; then
            echo -e "${RED}账户注册失败.${NC}"
            exit 1
        fi
        echo -e "${GREEN}账户注册成功.${NC}"
    fi
}

# 申请证书
apply_certificate() {
    get_acme_path
    register_account
    echo -e "${GREEN}请输入你的域名 (例如: example.com):${NC}"
    read DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        echo -e "${RED}域名不能为空.${NC}"
        return
    fi
    echo -e "${GREEN}请选择验证方式: (1) DNS 验证 (2) HTTP 验证${NC}"
    read METHOD
    case "$METHOD" in
        1)
            echo -e "${GREEN}使用 DNS 验证...${NC}"
            echo -e "${GREEN}请按照以下提示添加相应的 DNS TXT 记录:${NC}"
            # 使用手动 DNS 验证，需要用户手动添加 DNS TXT 记录
            $ACME_SH --issue --yes-I-know-dns-manual-mode-enough-please-dont-ask --dns manual -d "$DOMAIN" --debug 2
            ;;
        2)
            echo -e "${GREEN}使用 HTTP 验证...${NC}"
            while true; do
                read -p "请输入 webroot 目录 (例如: /var/www/html): " WEBROOT
                # 如果用户输入为空，提示并设置默认值
                if [[ -z "$WEBROOT" ]]; then
                    echo -e "${RED}webroot 目录不能为空.${NC}"
                    echo -e "${GREEN}将使用默认 webroot 目录: /var/www/html${NC}"
                    WEBROOT="/var/www/html"
                fi
                if [ -d "$WEBROOT" ]; then
                    break
                else
                    echo -e "${RED}指定的 webroot 目录不存在: $WEBROOT${NC}"
                    read -p "是否创建该目录? (y/n): " CREATE_DIR
                    case "$CREATE_DIR" in
                        y|Y)
                            mkdir -p "$WEBROOT"
                            if [ $? -eq 0 ]; then
                                echo -e "${GREEN}目录创建成功: $WEBROOT${NC}"
                                break
                            else
                                echo -e "${RED}无法创建目录: $WEBROOT${NC}"
                            fi
                            ;;
                        *)
                            echo -e "${RED}请提供一个有效的 webroot 目录路径.${NC}"
                            ;;
                    esac
                fi
            done
            $ACME_SH --issue -d "$DOMAIN" --webroot "$WEBROOT" --debug 2
            ;;
        *)
            echo -e "${RED}无效的选择.${NC}"
            return
            ;;
    esac

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}证书申请成功.${NC}"
    else
        echo -e "${RED}证书申请失败.${NC}"
    fi
}

# 管理证书
manage_certificates() {
    get_acme_path
    echo -e "${GREEN}acme.sh 证书管理:${NC}"
    echo "1. 列出所有证书"
    echo "2. 更新证书"
    echo "3. 安装证书到指定位置"
    echo "4. 删除证书"
    echo "0. 返回主菜单"
    read -p "请选择一个选项: " MANAGE_CHOICE

    case "$MANAGE_CHOICE" in
        1)
            $ACME_SH --list
            ;;
        2)
            echo -e "${GREEN}请输入要更新的域名:${NC}"
            read UPDATE_DOMAIN
            if [[ -z "$UPDATE_DOMAIN" ]]; then
                echo -e "${RED}域名不能为空.${NC}"
                return
            fi
            $ACME_SH --renew -d "$UPDATE_DOMAIN"
            ;;
        3)
            echo -e "${GREEN}请输入域名:${NC}"
            read INSTALL_DOMAIN
            if [[ -z "$INSTALL_DOMAIN" ]]; then
                echo -e "${RED}域名不能为空.${NC}"
                return
            fi
            echo -e "${GREEN}请输入目标路径 (例如: /etc/ssl/certs):${NC}"
            read TARGET_PATH
            if [[ -z "$TARGET_PATH" ]]; then
                echo -e "${RED}目标路径不能为空.${NC}"
                return
            fi
            $ACME_SH --install-cert -d "$INSTALL_DOMAIN" \
                --key-file "$TARGET_PATH/$INSTALL_DOMAIN.key" \
                --fullchain-file "$TARGET_PATH/$INSTALL_DOMAIN.crt"
            ;;
        4)
            echo -e "${GREEN}请输入要删除的域名:${NC}"
            read DELETE_DOMAIN
            if [[ -z "$DELETE_DOMAIN" ]]; then
                echo -e "${RED}域名不能为空.${NC}"
                return
            fi
            $ACME_SH --remove -d "$DELETE_DOMAIN"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效的选择，请重新选择.${NC}"
            ;;
    esac
}

# 卸载 acme.sh
uninstall_acme() {
    get_acme_path
    echo -e "${GREEN}正在卸载 acme.sh...${NC}"
    $ACME_SH --uninstall
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}acme.sh 卸载成功.${NC}"
    else
        echo -e "${RED}acme.sh 卸载失败.${NC}"
    fi
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${GREEN}===== ACME 一键管理脚本 =====${NC}"
        echo "1. 安装 acme.sh"
        echo "2. 申请证书"
        echo "3. 管理证书"
        echo "4. 卸载 acme.sh"
        echo "0. 退出脚本"
        echo -e "${GREEN}================================${NC}"
        read -p "请选择一个选项: " CHOICE

        case "$CHOICE" in
            1)
                install_dependencies
                install_acme
                ;;
            2)
                apply_certificate
                ;;
            3)
                manage_certificates
                ;;
            4)
                uninstall_acme
                ;;
            0)
                echo -e "${GREEN}退出脚本. 再见!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择，请重新选择.${NC}"
                ;;
        esac
    done
}

# 执行脚本
check_root
detect_os
main_menu
