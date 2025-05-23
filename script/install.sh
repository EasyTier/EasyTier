#!/bin/bash

RED_COLOR='\e[1;31m'
GREEN_COLOR='\e[1;32m'
YELLOW_COLOR='\e[1;33m'
BLUE_COLOR='\e[1;34m'
PINK_COLOR='\e[1;35m'
SHAN='\e[1;33;5m'
RES='\e[0m'

HELP() {
  echo -e "\r\n${GREEN_COLOR}EasyTier Installation Script Help${RES}\r\n"
  echo "Usage: ./install.sh [command] [options]"
  echo
  echo "Commands:"
  echo "  install    Install EasyTier"
  echo "  uninstall  Uninstall EasyTier"
  echo "  update     Update EasyTier to the latest version"
  echo "  help       Show this help message"
  echo
  echo "Options:"
  echo "  --skip-folder-verify  Skip folder verification during installation"
  echo "  --skip-folder-fix     Skip automatic folder path fixing"
  echo "  --no-gh-proxy        Disable GitHub proxy"
  echo "  --gh-proxy URL       Set custom GitHub proxy URL"
  echo
  echo "Examples:"
  echo "  ./install.sh install /opt/easytier"
  echo "  ./install.sh install --skip-folder-verify"
  echo "  ./install.sh install --no-gh-proxy"
  echo "  ./install.sh install --gh-proxy https://your-proxy.com/"
  echo "  ./install.sh update"
  echo "  ./install.sh uninstall"
}

# Show help if no arguments or help command is used
if [ $# -eq 0 ] || [ "$1" = "help" ]; then
  HELP
  exit 0
fi

# This script copy from alist , Thank for it!

SKIP_FOLDER_VERIFY=false
SKIP_FOLDER_FIX=false
NO_GH_PROXY=false
GH_PROXY='https://ghfast.top/'

COMMEND=$1
shift

# Check path
if [[ "$#" -ge 1 && ! "$1" == --* ]]; then
    INSTALL_PATH=$1
    shift
fi

# Check other option
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-folder-verify) SKIP_FOLDER_VERIFY=true ;;
        --skip-folder-fix) SKIP_FOLDER_FIX=true ;;
        --no-gh-proxy) NO_GH_PROXY=true ;;
        --gh-proxy) 
            if [ -n "$2" ]; then
                GH_PROXY=$2
                shift
            else
                echo "Error: --gh-proxy requires a URL"
                exit 1
            fi
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$INSTALL_PATH" ]; then
    INSTALL_PATH='/opt/easytier'
fi

if [[ "$INSTALL_PATH" == */ ]]; then
    INSTALL_PATH=${INSTALL_PATH%?}
fi

if ! $SKIP_FOLDER_FIX && ! [[ "$INSTALL_PATH" == */easytier ]]; then
    INSTALL_PATH="$INSTALL_PATH/easytier"
fi

echo INSTALL PATH : $INSTALL_PATH
echo SKIP FOLDER FIX : $SKIP_FOLDER_FIX
echo SKIP FOLDER VERIFY : $SKIP_FOLDER_VERIFY

# clear

# check if unzip is installed
if ! command -v unzip >/dev/null 2>&1; then
  echo -e "\r\n${RED_COLOR}Error: unzip is not installed${RES}\r\n"
  exit 1
fi

# check if curl is installed
if ! command -v curl >/dev/null 2>&1; then
  echo -e "\r\n${RED_COLOR}Error: curl is not installed${RES}\r\n"
  exit 1
fi

echo -e "\r\n${RED_COLOR}----------------------NOTICE----------------------${RES}\r\n"
echo " This is a temporary script to install EasyTier "
echo " EasyTier requires a dedicated empty folder to install"
echo " EasyTier is a developing product and may have some issues "
echo " Using EasyTier requires some basic skills "
echo " You need to face the risks brought by using EasyTier at your own risk "
echo -e "\r\n${RED_COLOR}-------------------------------------------------${RES}\r\n"

# Get platform
if command -v arch >/dev/null 2>&1; then
  platform=$(arch)
else
  platform=$(uname -m)
fi

case "$platform" in
  amd64 | x86_64)
    ARCH="x86_64"
    ;;
  arm64 | aarch64 | *armv8*)
    ARCH="aarch64"
    ;;
  *armv7*)
    ARCH="armv7"
    ;;
  *arm*)
    ARCH="arm"
    ;;
  mips)
    ARCH="mips"
    ;;
  mipsel)
    ARCH="mipsel"
    ;;
  *)
    ARCH="UNKNOWN"
    ;;
esac

# support hf
if [[ "$ARCH" == "armv7" || "$ARCH" == "arm" ]]; then
  if cat /proc/cpuinfo | grep Features | grep -i 'half' >/dev/null 2>&1; then
    ARCH=${ARCH}hf
  fi
fi

echo -e "\r\n${GREEN_COLOR}Your platform: ${ARCH} (${platform}) ${RES}\r\n" 1>&2

if [ "$(id -u)" != "0" ]; then
  echo -e "\r\n${RED_COLOR}This script requires run as Root !${RES}\r\n" 1>&2
  exit 1
elif [ "$ARCH" == "UNKNOWN" ]; then
  echo -e "\r\n${RED_COLOR}Opus${RES}, this script do not support your platform\r\nTry ${GREEN_COLOR}install by hand${RES}\r\n"
  exit 1
fi

# Detect init system
if command -v systemctl >/dev/null 2>&1; then
  INIT_SYSTEM="systemd"
elif command -v rc-update >/dev/null 2>&1; then
  INIT_SYSTEM="openrc"
else
  echo -e "\r\n${RED_COLOR}Error: Unsupported init system (neither systemd nor OpenRC found)${RES}\r\n"
  exit 1
fi


CHECK() {
  if ! $SKIP_FOLDER_VERIFY; then
    if [ -f "$INSTALL_PATH/easytier-core" ]; then
      echo "There is EasyTier in $INSTALL_PATH. Please choose other path or use \"update\""
        echo -e "Or use Try ${GREEN_COLOR}--skip-folder-verify${RES} to skip"
      exit 0
    fi
  fi

  if [ ! -d "$INSTALL_PATH/" ]; then
    mkdir -p $INSTALL_PATH
  else
    # Check weather path is empty
    if ! $SKIP_FOLDER_VERIFY; then
      if [ -n "$(ls -A $INSTALL_PATH)" ]; then
        echo "EasyTier requires to be installed in an empty directory. Please choose a empty path"
        echo -e "Or use Try ${GREEN_COLOR}--skip-folder-verify${RES} to skip"
        echo -e "Current path: $INSTALL_PATH ( use ${GREEN_COLOR}--skip-folder-fix${RES} to disable folder fix )"
        exit 1
      fi
    fi
  fi
}

INSTALL() {
  # Get version number
  RESPONSE=$(curl -s "https://api.github.com/repos/EasyTier/EasyTier/releases/latest")
  LATEST_VERSION=$(echo "$RESPONSE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  LATEST_VERSION=$(echo -e "$LATEST_VERSION" | tr -d '[:space:]')

  if [ -z "$LATEST_VERSION" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, failure to get latest version. Check your internet\r\nOr try ${GREEN_COLOR}install by hand${RES}\r\n"
    exit 1
  fi

  # Download
  echo -e "\r\n${GREEN_COLOR}Downloading EasyTier $LATEST_VERSION ...${RES}"
  rm -rf /tmp/easytier_tmp_install.zip
  BASE_URL="https://github.com/EasyTier/EasyTier/releases/latest/download/easytier-linux-${ARCH}-${LATEST_VERSION}.zip"
  DOWNLOAD_URL=$($NO_GH_PROXY && echo "$BASE_URL" || echo "${GH_PROXY}${BASE_URL}")
  echo -e "Download URL: ${GREEN_COLOR}${DOWNLOAD_URL}${RES}"
  curl -L ${DOWNLOAD_URL} -o /tmp/easytier_tmp_install.zip $CURL_BAR

  # Unzip resource
  echo -e "\r\n${GREEN_COLOR}Unzip resource ...${RES}"
  unzip -o /tmp/easytier_tmp_install.zip -d $INSTALL_PATH/
  mkdir $INSTALL_PATH/config
  mv $INSTALL_PATH/easytier-linux-${ARCH}/* $INSTALL_PATH/
  rm -rf $INSTALL_PATH/easytier-linux-${ARCH}/
  chmod +x $INSTALL_PATH/easytier-core $INSTALL_PATH/easytier-cli
  if [ -f $INSTALL_PATH/easytier-core ] || [ -f $INSTALL_PATH/easytier-cli ]; then
    echo -e "${GREEN_COLOR} Download successfully! ${RES}"
  else
    echo -e "${RED_COLOR} Download failed! ${RES}"
    exit 1
  fi
}

INIT() {
  if [ ! -f "$INSTALL_PATH/easytier-core" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, unable to find EasyTier\r\n"
    exit 1
  fi

  # Create default blank file config
  cat >$INSTALL_PATH/config/default.conf <<EOF
instance_name = "default"
dhcp = true
listeners = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
    "wg://0.0.0.0:11011",
    "ws://0.0.0.0:11011/",
    "wss://0.0.0.0:11012/",
]
exit_nodes = []
rpc_portal = "0.0.0.0:0"

[[peer]]
uri = "tcp://public.easytier.top:11010"

[network_identity]
network_name = "default"
network_secret = "default"

[flags]
default_protocol = "udp"
dev_name = ""
enable_encryption = true
enable_ipv6 = true
mtu = 1380
latency_first = false
enable_exit_node = false
no_tun = false
use_smoltcp = false
foreign_network_whitelist = "*"
disable_p2p = false
relay_all_peer_rpc = false
disable_udp_hole_punching = false

EOF

  # Create init script
  if [ "$INIT_SYSTEM" = "openrc" ]; then
    cat >/etc/init.d/easytier <<EOF
#!/sbin/openrc-run

name="EasyTier"
description="EasyTier Service"
command="$INSTALL_PATH/easytier-core"
command_args="-c $INSTALL_PATH/config/default.conf"
command_user="nobody:nobody"
command_background=true

pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
  need net
}


EOF
    chmod +x /etc/init.d/easytier
  fi

  # Create systemd
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    cat >/etc/systemd/system/easytier@.service <<EOF
[Unit]
Description=EasyTier Service
Wants=network.target
After=network.target network.service
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_PATH
ExecStart=$INSTALL_PATH/easytier-core -c $INSTALL_PATH/config/%i.conf
Restart=always
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF
  fi

#   # Create run script
#   cat >$INSTALL_PATH/run.sh <<EOF
# $INSTALL_PATH/easytier-core
# EOF

  # Startup
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl daemon-reload
    systemctl enable easytier@default >/dev/null 2>&1
    systemctl start easytier@default
  else
    rc-update add easytier default
    rc-service easytier start
  fi

  # For issues from the previous version
  rm -rf /etc/systemd/system/easytier.service
  rm -rf /usr/bin/easytier-core
  rm -rf /usr/bin/easytier-cli

  # Add link
  ln -s $INSTALL_PATH/easytier-core /usr/sbin/easytier-core
  ln -s $INSTALL_PATH/easytier-cli /usr/sbin/easytier-cli
}

SUCCESS() {
  clear
  echo " Install EasyTier successfully!"
  echo -e "\r\nDefault Port: ${GREEN_COLOR}11010(UDP+TCP)${RES}, Notice allowing in firewall!\r\n"
  echo -e "Default Network Name: ${GREEN_COLOR}default${RES}, Please change it to your own network name!\r\n"

  echo -e "Now EasyTier supports multiple config files. You can create config files in the ${GREEN_COLOR}${INSTALL_PATH}/config/${RES} folder"
  echo -e "For more information, please check the documents in official site"
  echo -e "The management example of a single configuration file is as follows"

  echo
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    echo -e "Status: ${GREEN_COLOR}systemctl status easytier@default${RES}"
    echo -e "Start: ${GREEN_COLOR}systemctl start easytier@default${RES}"
    echo -e "Restart: ${GREEN_COLOR}systemctl restart easytier@default${RES}"
    echo -e "Stop: ${GREEN_COLOR}systemctl stop easytier@default${RES}"
  else
    echo -e "Status: ${GREEN_COLOR}rc-service easytier status${RES}"
    echo -e "Start: ${GREEN_COLOR}rc-service easytier start${RES}"
    echo -e "Restart: ${GREEN_COLOR}rc-service easytier restart${RES}"
    echo -e "Stop: ${GREEN_COLOR}rc-service easytier stop${RES}"
  fi
  echo
}

UNINSTALL() {
  echo -e "\r\n${GREEN_COLOR}Uninstall EasyTier ...${RES}\r\n"
  echo -e "${GREEN_COLOR}Stop process ...${RES}"
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    systemctl disable "easytier@*" >/dev/null 2>&1
    systemctl stop "easytier@*" >/dev/null 2>&1
  else
    rc-update del easytier
    rc-service easytier stop
  fi
  echo -e "${GREEN_COLOR}Delete files ...${RES}"
  if [ "$INIT_SYSTEM" = "systemd" ]; then
    rm -rf $INSTALL_PATH /etc/systemd/system/easytier.service /usr/bin/easytier-core /usr/bin/easytier-cli /etc/systemd/system/easytier@.service /usr/sbin/easytier-core /usr/sbin/easytier-cli
    systemctl daemon-reload
  else
    rm -rf $INSTALL_PATH /etc/init.d/easytier /usr/bin/easytier-core /usr/bin/easytier-cli /usr/sbin/easytier-core /usr/sbin/easytier-cli
  fi
  echo -e "\r\n${GREEN_COLOR}EasyTier was removed successfully! ${RES}\r\n"
}

UPDATE() {
  if [ ! -f "$INSTALL_PATH/easytier-core" ]; then
    echo -e "\r\n${RED_COLOR}Opus${RES}, unable to find EasyTier\r\n"
    exit 1
  else
    echo
    echo -e "${GREEN_COLOR}Stopping EasyTier process${RES}\r\n"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
      systemctl stop "easytier@*"
    else
      rc-service easytier stop
    fi
    # Backup
    rm -rf /tmp/easytier_tmp_update
    mkdir -p  /tmp/easytier_tmp_update
    cp -a $INSTALL_PATH/* /tmp/easytier_tmp_update/
    INSTALL
    if [ -f $INSTALL_PATH/easytier-core ]; then
      echo -e "${GREEN_COLOR} Verify successfully ${RES}"
    else
      echo -e "${RED_COLOR} Download failed, unable to update${RES}"
      echo "Rollback all ..."
      rm -rf $INSTALL_PATH/*
      mv /tmp/easytier_tmp_update/* $INSTALL_PATH/
      if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl start "easytier@*"
      else
        rc-service easytier start
      fi
      exit 1
    fi
    echo -e "\r\n${GREEN_COLOR} Starting EasyTier process${RES}"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
      systemctl start "easytier@*"
    else
      rc-service easytier start
    fi
    echo -e "\r\n${GREEN_COLOR} EasyTier was updated successfully! ${RES}\r\n"
    echo -e "\r\n${GREEN_COLOR} EasyTier was the latest stable version! ${RES}\r\n"
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

echo $COMMEND

if [ "$COMMEND" = "uninstall" ]; then
  UNINSTALL
elif [ "$COMMEND" = "update" ]; then
  UPDATE
elif [ "$COMMEND" = "install" ]; then
  CHECK
  INSTALL
  INIT
  if [ -f "$INSTALL_PATH/easytier-core" ]; then
    SUCCESS
  else
    echo -e "${RED_COLOR} Install fail, try install by hand${RES}"
  fi
else
  echo -e "${RED_COLOR} Error Command ${RES}\n\r"
  echo " ALLOW:"
  echo -e "\n\r${GREEN_COLOR} install, uninstall, update, help ${RES}"
fi

rm -rf /tmp/easytier_tmp_*