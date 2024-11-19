#!/bin/bash

# acme_manager.sh - 一键安装和管理 acme.sh 脚本
# 适用于多种 Linux 发行版和 macOS

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否以root权限运行
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}请以root用户或使用sudo运行此脚本.${NC}"
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
            apt install -y curl socat
            ;;
        yum)
            yum install -y epel-release
            yum install -y curl socat
            ;;
        pacman)
            pacman -Sy --noconfirm curl socat
            ;;
        brew)
            brew install curl socat
            ;;
        *)
            echo -e "${RED}不支持的操作系统或包管理器: $OS${NC}"
            exit 1
            ;;
    esac
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

# 申请证书
apply_certificate() {
    get_acme_path
    echo -e "${GREEN}请输入你的域名 (例如: example.com):${NC}"
    read DOMAIN
    echo -e "${GREEN}请选择验证方式: (1) DNS 验证 (2) HTTP 验证${NC}"
    read METHOD
    case "$METHOD" in
        1)
            echo -e "${GREEN}使用 DNS 验证...${NC}"
            $ACME_SH --issue --dns -d "$DOMAIN" --yes-I-know-dns-manual-mode-enough-please-dont-ask
            ;;
        2)
            echo -e "${GREEN}使用 HTTP 验证...${NC}"
            $ACME_SH --issue -d "$DOMAIN" --webroot /var/www/html
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
            $ACME_SH --renew -d "$UPDATE_DOMAIN"
            ;;
        3)
            echo -e "${GREEN}请输入域名:${NC}"
            read INSTALL_DOMAIN
            echo -e "${GREEN}请输入目标路径 (例如: /etc/ssl/certs):${NC}"
            read TARGET_PATH
            $ACME_SH --install-cert -d "$INSTALL_DOMAIN" \
                --key-file "$TARGET_PATH/$INSTALL_DOMAIN.key" \
                --fullchain-file "$TARGET_PATH/$INSTALL_DOMAIN.crt"
            ;;
        4)
            echo -e "${GREEN}请输入要删除的域名:${NC}"
            read DELETE_DOMAIN
            $ACME_SH --remove -d "$DELETE_DOMAIN"
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}无效的选择.${NC}"
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
