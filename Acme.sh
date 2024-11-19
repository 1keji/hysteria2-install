#!/usr/bin/env bash

# Function to check and install dependencies
install_dependency() {
  if ! command -v $1 &>/dev/null; then
    echo "$1 is not installed. Installing..."
    if [ -x "$(command -v apt)" ]; then
      sudo apt update && sudo apt install -y $1
    elif [ -x "$(command -v yum)" ]; then
      sudo yum install -y $1
    elif [ -x "$(command -v dnf)" ]; then
      sudo dnf install -y $1
    elif [ -x "$(command -v pacman)" ]; then
      sudo pacman -Sy --noconfirm $1
    else
      echo "Unsupported package manager. Please install $1 manually."
      exit 1
    fi
  else
    echo "$1 is already installed."
  fi
}

# Function to install Acme.sh
install_acme() {
  if [ ! -d "$HOME/.acme.sh" ]; then
    echo "Installing Acme.sh..."
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
      echo "Failed to install Acme.sh. Please check your network connection and try again."
      exit 1
    fi
    echo "Acme.sh installed successfully."
  else
    echo "Acme.sh is already installed. Updating to the latest version..."
    $HOME/.acme.sh/acme.sh --upgrade
  fi

  # Export Acme.sh to PATH
  if ! grep -q 'export PATH="$HOME/.acme.sh:\$PATH"' ~/.bashrc; then
    echo 'export PATH="$HOME/.acme.sh:\$PATH"' >> ~/.bashrc
    source ~/.bashrc
    echo "Acme.sh path added to .bashrc."
  fi

  echo "Acme.sh is ready to use!"
}

# Function to check Acme.sh status
check_acme_status() {
  if command -v acme.sh &>/dev/null; then
    acme.sh --version
    if [ $? -eq 0 ]; then
      echo "Acme.sh is installed and functioning properly."
    else
      echo "Acme.sh is not functioning correctly. Please troubleshoot manually."
    fi
  else
    echo "Acme.sh is not installed."
  fi
}

# Function to apply for SSL certificate
apply_certificate() {
  read -p "Enter domain name for the certificate: " domain
  $HOME/.acme.sh/acme.sh --issue -d $domain --standalone
  if [ $? -eq 0 ]; then
    echo "Certificate for $domain has been successfully issued."
  else
    echo "Failed to issue certificate for $domain. Please check the logs and try again."
  fi
}

# Function to uninstall Acme.sh
uninstall_acme() {
  if [ -d "$HOME/.acme.sh" ]; then
    $HOME/.acme.sh/acme.sh --uninstall
    echo "Acme.sh has been uninstalled."
  else
    echo "Acme.sh is not installed."
  fi
}

# Main menu
while true; do
  echo ""
  echo "Acme.sh Management Script"
  echo "1. Install/Update Acme.sh"
  echo "2. Check Acme.sh Status"
  echo "3. Apply for SSL Certificate"
  echo "4. Uninstall Acme.sh"
  echo "0. Exit"
  read -p "Enter your choice: " choice

  case $choice in
    1)
      install_acme
      ;;
    2)
      check_acme_status
      ;;
    3)
      apply_certificate
      ;;
    4)
      uninstall_acme
      ;;
    0)
      echo "Exiting..."
      exit 0
      ;;
    *)
      echo "Invalid choice. Please enter a valid option."
      ;;
  esac

done
