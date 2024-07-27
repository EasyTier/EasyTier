#!/bin/bash

# This script copy from alist , Thank for it!

# INSTALL_PATH='/opt/easytier'
VERSION='latest'

if [ ! -n "$2" ]; then
  INSTALL_PATH='/opt/easytier'
else
  if [[ $2 == */ ]]; then
    INSTALL_PATH=${2%?}
  else
    INSTALL_PATH=$2
  fi
  if ! [[ $INSTALL_PATH == */easytier ]]; then
    INSTALL_PATH="$INSTALL_PATH/easytier"
  fi
fi

RED_COLOR='\e[1;31m'
GREEN_COLOR='\e[1;32m'
YELLOW_COLOR='\e[1;33m'
BLUE_COLOR='\e[1;34m'
PINK_COLOR='\e[1;35m'
SHAN='\e[1;33;5m'
RES='\e[0m'
clear

echo -e "\r\n${RED_COLOR}----------------------NOTICE----------------------${RES}\r\n"
echo " This is a temporary script to install Easytier "
echo " Easytier is a developing product and may have some issues "
echo " Using Easytier requires some basic skills "
echo " You need to face the risks brought by using Easytier at your own risk "
echo -e "\r\n${RED_COLOR}-------------------------------------------------${RES}\r\n"

read -p "Enter \"yes\" to accept our policy and continue: " -r agreement
if [[ ! "$agreement" =~ ^[Yy]es$ ]]
then
    echo "You do not accept your policy, the script will exit ..."
    exit 1
fi

# Get platform
if command -v arch >/dev/null 2>&1; then
  platform=$(arch)
else
  platform=$(uname -m)
fi

echo -e "\r\n${GREEN_COLOR}Your platform: ${platform} ${RES}\r\n" 1>&2

ARCH="UNKNOWN"

if [ "$platform" = "amd64" ] || [ "$platform" = "x86_64" ]; then
  ARCH="x86_64"
  SUFFIX="musl-"
elif [ "$platform" = "arm64" ] || [ "$platform" = "aarch64" ] || [ "$platform" = "armv8" ]; then
  ARCH="aarch64"
  SUFFIX="musleabihf-"
elif [ "$platform" = "armv7l" ] || [ "$platform" = "armv7" ]; then
  ARCH="armv7"
  SUFFIX="musleabihf-"
fi


GH_PROXY='https://mirror.ghproxy.com/'

if [ "$(id -u)" != "0" ]; then
  echo -e "\r\n${RED_COLOR}This script requires run as Root !${RES}\r\n" 1>&2
  exit 1
elif [ "$ARCH" == "UNKNOWN" ]; then
  echo -e "\r\n${RED_COLOR}Opus${RES}, this script do not support your platfrom\r\nTry ${GREEN_COLOR}install by band${RES}\r\n"
  exit 1
elif ! command -v systemctl >/dev/null 2>&1; then
  echo -e "\r\n${RED_COLOR}Opus${RES}, your Linux do not support systemctl\r\nnTry ${GREEN_COLOR}install by band${RES}\r\n"
  exit 1
else
  if command -v netstat >/dev/null 2>&1; then
    check_port=$(netstat -lnp | grep 11010 | awk '{print $7}' | awk -F/ '{print $1}')
  else
    echo -e "${GREEN_COLOR}Check port ...${RES}"
    if command -v yum >/dev/null 2>&1; then
      yum install net-tools -y >/dev/null 2>&1
      check_port=$(netstat -lnp | grep 11010 | awk '{print $7}' | awk -F/ '{print $1}')
    else
      apt-get update >/dev/null 2>&1
      apt-get install net-tools -y >/dev/null 2>&1
      check_port=$(netstat -lnp | grep 11010 | awk '{print $7}' | awk -F/ '{print $1}')
    fi
  fi
fi

CHECK() {
  if [ -f "$INSTALL_PATH/easytier-core" ]; then
    echo "There is easytier in $INSTALL_PATH. Please choose other path or use \"update\""
    exit 0
  fi
  if [ $check_port ]; then
    kill -9 $check_port
  fi
  if [ ! -d "$INSTALL_PATH/" ]; then
    mkdir -p $INSTALL_PATH
  else
    rm -rf $INSTALL_PATH && mkdir -p $INSTALL_PATH
  fi
}

INSTALL() {
  # Get version number
  RESPONSE=$(curl -s "https://api.github.com/repos/EasyTier/EasyTier/releases/latest")
  LATEST_VERSION=$(echo "$RESPONSE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  LATEST_VERSION=$(echo -e "$LATEST_VERSION" | tr -d '[:space:]')

  if [ -z "$LATEST_VERSION" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, failure to get latest version. Check your internel\r\nOr try ${GREEN_COLOR}install by band${RES}\r\n"
    exit 1
  fi

  # Download
  echo -e "\r\n${GREEN_COLOR}下载 Easytier $LATEST_VERSION ...${RES}"
  rm -rf /tmp/easytier_tmp_install.zip
  curl -L ${GH_PROXY}https://github.com/EasyTier/EasyTier/releases/latest/download/easytier-$ARCH-unknown-linux-${SUFFIX}${LATEST_VERSION}.zip -o /tmp/easytier_tmp_install.zip $CURL_BAR
  # Unzip resource
  echo -e "\r\n${GREEN_COLOR}Unzip resource ...${RES}"
  unzip /tmp/easytier_tmp_install.zip -d $INSTALL_PATH/

  if [ -f $INSTALL_PATH/easytier-core ] || [ -f $INSTALL_PATH/easytier-cli ]; then
    echo -e "${GREEN_COLOR} Download successfully! ${RES}"
  else
    echo -e "${RED_COLOR} Download failed! ${RES}"
    exit 1
  fi
}

INIT() {
  if [ ! -f "$INSTALL_PATH/easytier-core" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, unable to find Easytier\r\n"
    exit 1
  fi

  # Create systemd
  cat >/etc/systemd/system/easytier.service <<EOF
[Unit]
Description=EasyTier Service
Wants=network.target
After=network.target network.service

[Service]
Type=simple
WorkingDirectory=$INSTALL_PATH
ExecStart=/bin/bash $INSTALL_PATH/run.sh

[Install]
WantedBy=multi-user.target
EOF

  # Create run script
  cat >$INSTALL_PATH/run.sh <<EOF
$INSTALL_PATH/easytier-core
EOF

  # Startup
  systemctl daemon-reload
  systemctl enable easytier >/dev/null 2>&1
  systemctl start easytier

  # Add link
  ln -s $INSTALL_PATH/easytier-core /usr/bin/easytier-core
  ln -s $INSTALL_PATH/easytier-cli /usr/bin/easytier-cli
}

SUCCESS() {
  clear
  echo " Install Easytier successfully！"
  echo -e "\r\nDefault Port: ${GREEN_COLOR}11010(UDP+TCP)${RES}, Notice allowing in firwall!\r\n"

  echo -e "Staartup script path: ${GREEN_COLOR}$INSTALL_PATH/run.sh${RES}\n\r\n\rFor more advanced opinions, please modify the startup script"

  echo
  echo -e "Status: ${GREEN_COLOR}systemctl status easytier${RES}"
  echo -e "Start: ${GREEN_COLOR}systemctl start easytier${RES}"
  echo -e "Restart: ${GREEN_COLOR}systemctl restart easytier${RES}"
  echo -e "Stop: ${GREEN_COLOR}systemctl stop easytier${RES}"
  echo
}

UNINSTALL() {
  echo -e "\r\n${GREEN_COLOR}Uninstall Easytier ...${RES}\r\n"
  echo -e "${GREEN_COLOR}Stop process ...${RES}"
  systemctl disable easytier >/dev/null 2>&1
  systemctl stop easytier >/dev/null 2>&1
  echo -e "${GREEN_COLOR}Delete files ...${RES}"
  rm -rf $INSTALL_PATH /etc/systemd/system/easytier.service /usr/bin/easytier-core /usr/bin/easytier-cli
  systemctl daemon-reload
  echo -e "\r\n${GREEN_COLOR}Easytier was removed successfully! ${RES}\r\n"
}

UPDATE() {
  if [ ! -f "$INSTALL_PATH/easytier-core" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, unable to find Easytier\r\n"
    exit 1
  else
    echo
    echo -e "${GREEN_COLOR}Stopping Easytier process${RES}\r\n"
    systemctl stop easytier
    # Backup
    rm -rf /tmp/easytier_tmp_update
    mkdir -p  /tmp/easytier_tmp_update
    cp -a $INSTALL_PATH/* /tmp/easytier_tmp_update/
    INSTALL
    if [ -f $INSTALL_PATH/easytier-core ]; then
      echo -e "${GREEN_COLOR} Download successfully ${RES}"
    else
      echo -e "${RED_COLOR} Download failed, unable to update${RES}"
      echo "Rollback all ..."
      rm -rf $INSTALL_PATH/*
      mv /tmp/easytier_tmp_update/* $INSTALL_PATH/
      systemctl start easytier
      exit 1
    fi
    echo -e "\r\n${GREEN_COLOR} Starting easytier process${RES}"
    systemctl start easytier
    echo -e "\r\n${GREEN_COLOR} Easytier was the latest stable version! ${RES}\r\n"
  fi
}

# CURL progress
if curl --help | grep progress-bar >/dev/null 2>&1; then # $CURL_BAR
  CURL_BAR="--progress-bar"
fi

# The temp directory must exist
if [ ! -d "/tmp" ]; then
  mkdir -p /tmp
fi

if [ "$1" = "uninstall" ]; then
  UNINSTALL
elif [ "$1" = "update" ]; then
  UPDATE
elif [ "$1" = "install" ]; then
  CHECK
  INSTALL
  INIT
  if [ -f "$INSTALL_PATH/easytier-core" ]; then
    SUCCESS
  else
    echo -e "${RED_COLOR} Install fail, try install by hand${RES}"
  fi
else
  echo -e "${RED_COLOR} Error Commend ${RES}\n\r"
  echo " ALLOW:"
  echo -e "\n\r${GREEN_COLOR} install, uninstall, update ${RES}"
fi

rm -f /tmp/easytier_tmp_*