#!/bin/bash

# Color setup - enable only if terminal supports colors
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED_COLOR='\033[0;31m'
    GREEN_COLOR='\033[0;32m'
    YELLOW_COLOR='\033[0;33m'
    BLUE_COLOR='\033[0;34m'
    PINK_COLOR='\033[0;35m'
    SHAN='\033[0;5;31m'
    RES='\033[0m'
else
    RED_COLOR=''
    GREEN_COLOR=''
    YELLOW_COLOR=''
    BLUE_COLOR=''
    PINK_COLOR=''
    SHAN=''
    RES=''
fi

# --- FHS paths ---
BIN_PATH="/usr/local/bin"
CONFIG_PATH="/etc/easytier"
# ---

HELP() {
  echo -e "\r\n${GREEN_COLOR}EasyTier Installation Script Help${RES}\r\n"
  echo "Usage: ./install.sh [command] [options]"
  echo
  echo "Commands:"
  echo "  install    Install EasyTier to standard system paths"
  echo "  uninstall  Uninstall EasyTier from system paths"
  echo "  update     Update EasyTier binaries to the latest version"
  echo "  help       Show this help message"
  echo
  echo "Configuration Modes (mutually exclusive):"
  echo "  1. Config File Mode (Default):"
  echo "     -c <PATH>           Specify a custom config file path for the service."
  echo "                         If omitted, a default service using a template is created."
  echo
  echo "  2. Argument Mode:"
  echo "     -w \"ARGS\"          Run service with direct arguments, ignoring config files."
  echo "     -w <URL>           Smart detection: If URL detected, automatically converts to config server mode."
  echo "     --machine-id <ID>   (Only with -w or --config-server) Set a specific machine-id."
  echo
  echo "  3. Config Server Mode:"
  echo "     --config-server <URL> Connect to a config server for centralized management."
  echo "                         Supports username (official server) or full URL format."
  echo "     --machine-id <ID>   (Optional) Set a specific machine-id for device identification."
  echo
  echo "Other Options:"
  echo "  --no-gh-proxy        Disable GitHub proxy"
  echo "  --gh-proxy URL       Set custom GitHub proxy URL"
  echo
  echo "Examples:"
  echo "  ./install.sh install                                        # Default install, uses local config"
  echo "  ./install.sh install -c /etc/easytier/my.conf               # Install with custom config file"
  echo "  ./install.sh install -w \"--no-tun\" --machine-id srv1        # Install with direct arguments"
  echo "  ./install.sh install -w myteam --machine-id srv1            # Smart detection: config server mode"
  echo "  ./install.sh install -w https://config.company.com:22020/dept # Smart detection: custom server"
  echo "  ./install.sh install --config-server myteam --machine-id srv1 # Explicit config server mode"
  echo "  ./install.sh install --config-server udp://config.company.com:22020/dept # Explicit custom server"
}

# --- Main Script Logic ---

main() {
    # --- Variable initialization ---
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    NO_GH_PROXY=false
    GH_PROXY='https://ghfast.top/'

    # Mode flags and variables
    CONFIG_FILE_MODE_PATH=""
    ARG_MODE_ARGS=()
    CONFIG_SERVER_URL=""
    W_FLAG=false
    C_FLAG=false
    CONFIG_SERVER_FLAG=false

    COMMAND=$1
    shift

    # --- Argument Parsing ---
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -c)
                C_FLAG=true
                if [ -n "$2" ]; then 
                    if validate_path "$2" "config file"; then
                        CONFIG_FILE_MODE_PATH=$2
                    else
                        exit 1
                    fi
                    shift
                else 
                    echo -e "${RED_COLOR}Error: -c requires a path${RES}" >&2
                    exit 1
                fi
                ;;
            -w)
                if [ -n "$2" ]; then 
                    # Smart detection: if the argument looks like a config server URL, convert it
                    if is_config_server_url "$2"; then
                        echo -e "${BLUE_COLOR}Smart detection: Converting -w URL to config server mode${RES}" >&2
                        CONFIG_SERVER_FLAG=true
                        if validate_config_server_url "$2"; then
                            CONFIG_SERVER_URL=$2
                        else
                            exit 1
                        fi
                        ARG_MODE_ARGS+=("--config-server" "$2")
                    else
                        # Traditional -w argument mode
                        W_FLAG=true
                        ARG_MODE_ARGS+=("-w" "$2")
                    fi
                    shift
                else 
                    echo "Error: -w requires an argument string" >&2; exit 1
                fi
                ;;
            --machine-id)
                if [ -n "$2" ]; then ARG_MODE_ARGS+=("--machine-id" "$2"); shift; else echo "Error: --machine-id requires an argument" >&2; exit 1; fi
                ;;
            --config-server)
                CONFIG_SERVER_FLAG=true
                if [ -n "$2" ]; then 
                    if validate_config_server_url "$2"; then
                        CONFIG_SERVER_URL=$2
                    else
                        exit 1
                    fi
                    shift
                else 
                    echo -e "${RED_COLOR}Error: --config-server requires a URL or username${RES}" >&2
                    exit 1
                fi
                ;;
            --no-gh-proxy) NO_GH_PROXY=true ;;
            --gh-proxy)
                if [ -n "$2" ]; then GH_PROXY=$2; shift; else echo "Error: --gh-proxy requires a URL" >&2; exit 1; fi
                ;;
            *) echo "Unknown option: $1. Use './install.sh help' for usage." >&2; exit 1 ;;
    esac
        shift
    done

    # --- Argument Validation ---
    # Check for mutually exclusive configuration modes
    local mode_count=0
    $C_FLAG && mode_count=$((mode_count + 1))
    $W_FLAG && mode_count=$((mode_count + 1))
    $CONFIG_SERVER_FLAG && mode_count=$((mode_count + 1))
    
    if [ $mode_count -gt 1 ]; then
        echo -e "${RED_COLOR}Error: Configuration modes are mutually exclusive.${RES}" >&2
        echo -e "${YELLOW_COLOR}Choose only one of:${RES}" >&2
        echo -e "${YELLOW_COLOR}  -c <path>           Config file mode${RES}" >&2
        echo -e "${YELLOW_COLOR}  -w \"args\"           Argument mode${RES}" >&2
        echo -e "${YELLOW_COLOR}  --config-server <url> Config server mode${RES}" >&2
        exit 1
    fi

    # Check if --machine-id was used without -w or --config-server
    if ! $W_FLAG && ! $CONFIG_SERVER_FLAG; then
        for arg in "$@"; do
            if [[ $arg == "--machine-id" ]]; then
                echo -e "${RED_COLOR}Error: --machine-id can only be used with -w (argument mode) or --config-server (config server mode).${RES}" >&2
                exit 1
            fi
        done
    fi

    # --- Prerequisite Checks ---
    if ! command -v unzip >/dev/null 2>&1; then 
        handle_error "unzip is not installed" "Install unzip using: apt-get install unzip (Debian/Ubuntu) or yum install unzip (CentOS/RHEL) or brew install unzip (macOS)" "system"
        exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then 
        handle_error "curl is not installed" "Install curl using: apt-get install curl (Debian/Ubuntu) or yum install curl (CentOS/RHEL) or brew install curl (macOS)" "system"
        exit 1
    fi
    
    # Check if we have internet connection
    if ! curl -s --connect-timeout 5 https://github.com >/dev/null 2>&1; then
        handle_error "Unable to connect to GitHub" "Please check your internet connection and try again" "network"
        exit 1
    fi
    
    # Test config server connectivity if specified
    if $CONFIG_SERVER_FLAG; then
        test_config_server_connectivity "$CONFIG_SERVER_URL"
    fi

    # --- Display Notice ---
    echo -e "\r\n${RED_COLOR}----------------------NOTICE----------------------${RES}\r\n"
    echo " This script will install EasyTier to standard system paths."
    echo " Binaries will be placed in ${BIN_PATH}"
    echo " Configuration files will be placed in ${CONFIG_PATH}"
    echo -e "\r\n${RED_COLOR}-------------------------------------------------${RES}\r\n"

    # --- Platform Detection ---
    if command -v arch >/dev/null 2>&1; then platform=$(arch); else platform=$(uname -m); fi
    case "$platform" in
      amd64 | x86_64) ARCH="x86_64" ;;
      arm64 | aarch64 | *armv8*) ARCH="aarch64" ;;
      *armv7*) ARCH="armv7" ;;
      *arm*) ARCH="arm" ;;
      mips) ARCH="mips" ;;
      mipsel) ARCH="mipsel" ;;
      loongarch64) ARCH="loongarch64" ;;
      riscv64) ARCH="riscv64" ;;
      *) ARCH="UNKNOWN" ;;
esac
    if [[ "$ARCH" == "armv7" || "$ARCH" == "arm" ]]; then
      if [[ "$OS" == "linux" ]]; then
        # Linux: check /proc/cpuinfo for hard float support
        if cat /proc/cpuinfo 2>/dev/null | grep Features | grep -i 'half' >/dev/null 2>&1; then 
          ARCH=${ARCH}hf
        fi
      elif [[ "$OS" == "darwin" ]]; then
        # macOS: ARM64 doesn't need hf suffix, older ARM Macs are rare but check sysctl
        if sysctl -n hw.optional.arm.FEAT_DotProd 2>/dev/null >/dev/null || \
           sysctl -n hw.optional.arm.FEAT_RDM 2>/dev/null >/dev/null || \
           sysctl -n hw.optional.neon 2>/dev/null | grep -q '1$' 2>/dev/null; then
          ARCH=${ARCH}hf
        fi
      else
        # For other Unix-like systems, assume hard float support for ARMv7+
        # Most modern non-Linux ARM systems support hard float
        if [[ "$ARCH" == "armv7" ]]; then
          ARCH=${ARCH}hf
        fi
      fi
    fi
    echo -e "\r\n${GREEN_COLOR}Your platform: ${ARCH} (${platform}) on ${OS} ${RES}\r\n" 1>&2
    if [ "$ARCH" == "UNKNOWN" ]; then echo -e "\r\n${RED_COLOR}Oops${RES}, this script does not support your platform\r\n" >&2; exit 1; fi

    # --- Init System Detection ---
    if [ "$OS" = "darwin" ]; then 
        INIT_SYSTEM="launchd"
    elif command -v systemctl >/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif command -v rc-update >/dev/null 2>&1; then
        INIT_SYSTEM="openrc"
    else
        handle_error "Unsupported init system" "This script supports systemd, launchd (macOS), and OpenRC. Please check if your system uses one of these init systems." "system"
        exit 1
    fi

    # --- Main Execution ---
    case "$COMMAND" in
      install) CHECK && INSTALL && INIT && SUCCESS ;;
      uninstall) UNINSTALL ;;
      update) UPDATE ;;
      *) HELP ;;
esac
}

# --- Function Definitions ---

# Validate a file path to prevent directory traversal attacks
validate_path() {
    local path="$1"
    local purpose="$2"
    
    # Check if path is empty
    if [ -z "$path" ]; then
        echo -e "${RED_COLOR}Error: Empty path provided for $purpose${RES}" >&2
        return 1
    fi
    
    # Check for directory traversal attempts
    if [[ "$path" == *".."* ]] || [[ "$path" == *"~"* ]] || [[ "$path" == *"/"*"../"* ]]; then
        echo -e "${RED_COLOR}Error: Invalid path for $purpose: $path${RES}" >&2
        echo -e "${RED_COLOR}Path traversal attacks are not allowed${RES}" >&2
        return 1
    fi
    
    # Check if path starts with / (absolute path) - allowed but we should validate
    if [[ "$path" == /* ]]; then
        # For absolute paths, check if they're in allowed directories
        case "$path" in
            /etc/*|/usr/*|/opt/*|/var/*)
                # Allowed system directories
                ;;
            *)
                echo -e "${YELLOW_COLOR}Warning: Absolute path $path may be unsafe for $purpose${RES}" >&2
                ;;
        esac
    fi
    
    # For config files, ensure the directory exists or can be created
    if [[ "$purpose" == "config file" ]]; then
        local dir=$(dirname "$path" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "${RED_COLOR}Error: Invalid config file path: $path${RES}" >&2
            return 1
        fi
    fi
    
    return 0
}

# Check if a string looks like a config server URL
is_config_server_url() {
    local arg="$1"
    
    # First check if it's a full URL with protocol
    if [[ "$arg" =~ ^(udp|tcp|https?)://[^/]+(/.*)?$ ]]; then
        return 0
    fi
    
    # Then check if it's a simple username (but not starting with --)
    if [[ "$arg" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ "$arg" != --* ]]; then
        return 0
    fi
    
    return 1
}

# Validate config server URL format
validate_config_server_url() {
    local url="$1"
    
    # Check if URL is empty
    if [ -z "$url" ]; then
        echo -e "${RED_COLOR}Error: Empty config server URL${RES}" >&2
        return 1
    fi
    
    # Check for basic security issues
    if [[ "$url" == *".."* ]] || [[ "$url" == *";"* ]] || [[ "$url" == *"|"* ]] || [[ "$url" == *"&"* ]]; then
        echo -e "${RED_COLOR}Error: Invalid characters in config server URL: $url${RES}" >&2
        return 1
    fi
    
    # Accept different URL formats:
    # 1. Username only (will use official server): "admin", "myteam"
    # 2. Full URL: "udp://server:port/user", "tcp://server:port/user", "https://server:port/user"
    
    # Check if it's a simple username (alphanumeric, hyphens, underscores)
    if [[ "$url" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${BLUE_COLOR}Using official EasyTier config server with username: $url${RES}" >&2
        return 0
    fi
    
    # Check if it's a full URL
    if [[ "$url" =~ ^(udp|tcp|https?)://[^/]+(/.*)?$ ]]; then
        # Extract protocol, host, and path
        local protocol=$(echo "$url" | sed -n 's/^\([^:]*\):.*/\1/p')
        local host_part=$(echo "$url" | sed -n 's/^[^:]*:\/\/\([^/]*\).*/\1/p')
        
        # Validate protocol
        case "$protocol" in
            udp|tcp|http|https)
                ;;
            *)
                echo -e "${RED_COLOR}Error: Unsupported protocol in config server URL: $protocol${RES}" >&2
                echo -e "${YELLOW_COLOR}Supported protocols: udp, tcp, http, https${RES}" >&2
                return 1
                ;;
        esac
        
        # Basic host validation (not empty)
        if [ -z "$host_part" ]; then
            echo -e "${RED_COLOR}Error: Invalid host in config server URL: $url${RES}" >&2
            return 1
        fi
        
        echo -e "${BLUE_COLOR}Using custom config server: $url${RES}" >&2
        return 0
    fi
    
    # If we get here, the format is not recognized
    echo -e "${RED_COLOR}Error: Invalid config server URL format: $url${RES}" >&2
    echo -e "${YELLOW_COLOR}Expected formats:${RES}" >&2
    echo -e "${YELLOW_COLOR}  Username: myteam${RES}" >&2
    echo -e "${YELLOW_COLOR}  Full URL: udp://server:port/user${RES}" >&2
    echo -e "${YELLOW_COLOR}           tcp://server:port/user${RES}" >&2
    echo -e "${YELLOW_COLOR}           https://server:port/user${RES}" >&2
    return 1
}

# Test config server connectivity (optional, non-blocking)
test_config_server_connectivity() {
    local url="$1"
    
    # Skip connectivity test for username-only format (official server)
    if [[ "$url" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo -e "${BLUE_COLOR}Skipping connectivity test for official server (username: $url)${RES}" >&2
        return 0
    fi
    
    # Extract host and port from URL for basic connectivity test
    local host_port=""
    if [[ "$url" =~ ^[^:]*://([^/]+) ]]; then
        host_port="${BASH_REMATCH[1]}"
    else
        echo -e "${YELLOW_COLOR}Warning: Cannot extract host from URL for connectivity test: $url${RES}" >&2
        return 0
    fi
    
    # Extract host and port
    local host=$(echo "$host_port" | cut -d':' -f1)
    local port=$(echo "$host_port" | cut -d':' -f2)
    
    # If no port specified, use default based on protocol
    if [ "$port" = "$host" ]; then
        if [[ "$url" == https://* ]]; then
            port=443
        elif [[ "$url" == http://* ]]; then
            port=80
        else
            port=22020  # Default EasyTier config server port
        fi
    fi
    
    echo -e "${BLUE_COLOR}Testing connectivity to config server: $host:$port${RES}" >&2
    
    # Test connectivity with timeout
    if command -v nc >/dev/null 2>&1; then
        # Use netcat if available
        if timeout 5 nc -z "$host" "$port" >/dev/null 2>&1; then
            echo -e "${GREEN_COLOR}✓ Config server is reachable${RES}" >&2
            return 0
        else
            echo -e "${YELLOW_COLOR}⚠ Warning: Config server appears unreachable (host: $host, port: $port)${RES}" >&2
            echo -e "${YELLOW_COLOR}  This may be normal if the server is behind a firewall or uses custom protocols${RES}" >&2
            return 0  # Non-blocking warning
        fi
    elif command -v telnet >/dev/null 2>&1; then
        # Fallback to telnet
        if timeout 5 bash -c "echo '' | telnet $host $port" >/dev/null 2>&1; then
            echo -e "${GREEN_COLOR}✓ Config server is reachable${RES}" >&2
            return 0
        else
            echo -e "${YELLOW_COLOR}⚠ Warning: Config server appears unreachable (host: $host, port: $port)${RES}" >&2
            echo -e "${YELLOW_COLOR}  This may be normal if the server is behind a firewall or uses custom protocols${RES}" >&2
            return 0  # Non-blocking warning
        fi
    else
        echo -e "${YELLOW_COLOR}Note: Cannot test config server connectivity (nc/telnet not available)${RES}" >&2
        return 0
    fi
}

# Safely escape strings for service file usage
escape_string() {
    local string="$1"
    # Escape special characters that could break service file syntax
    printf '%s' "$string" | sed 's/\\/\\\\/g; s/"/\\\"/g; s/`/\\`/g; s/\$/\\$/g'
}


# Verify SHA256 checksum of a binary file
verify_sha256_checksum() {
    local binary_file="$1"
    local expected_checksum="$2"
    
    # Check if binary file exists
    if [ ! -f "$binary_file" ]; then
        echo -e "${RED_COLOR}Error: Binary file not found: $binary_file${RES}" >&2
        return 1
    fi
    
    # Check if sha256sum command is available
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo -e "${YELLOW_COLOR}Warning: sha256sum not found, skipping checksum verification${RES}" >&2
        return 0
    fi
    
    # Calculate actual checksum
    echo -e "${BLUE_COLOR}Calculating SHA256 checksum...${RES}"
    local actual_checksum=$(sha256sum "$binary_file" | cut -d' ' -f1)
    
    if [ -z "$actual_checksum" ]; then
        echo -e "${RED_COLOR}Error: Failed to calculate checksum${RES}" >&2
        return 1
    fi
    
    # Compare checksums
    if [ "$actual_checksum" = "$expected_checksum" ]; then
        echo -e "${GREEN_COLOR}SHA256 checksum verification successful${RES}"
        return 0
    else
        echo -e "${RED_COLOR}Error: SHA256 checksum verification failed${RES}" >&2
        echo -e "${RED_COLOR}Expected: $expected_checksum${RES}" >&2
        echo -e "${RED_COLOR}Actual:   $actual_checksum${RES}" >&2
        return 1
    fi
}

# Enhanced error handling with recovery suggestions
handle_error() {
    local error_message="$1"
    local recovery_suggestion="$2"
    local error_type="${3:-general}"
    
    echo -e "\r\n${RED_COLOR}=== ERROR ===${RES}" >&2
    echo -e "${RED_COLOR}Error: $error_message${RES}" >&2
    
    case "$error_type" in
        "network")
            echo -e "${YELLOW_COLOR}Recovery suggestions:${RES}" >&2
            echo -e "${YELLOW_COLOR}1. Check your internet connection${RES}" >&2
            echo -e "${YELLOW_COLOR}2. Try again later (GitHub may be temporarily unavailable)${RES}" >&2
            echo -e "${YELLOW_COLOR}3. Use --no-gh-proxy if you don't need GitHub proxy${RES}" >&2
            echo -e "${YELLOW_COLOR}4. Configure a different proxy with --gh-proxy <url>${RES}" >&2
            ;;
        "permission")
            echo -e "${YELLOW_COLOR}Recovery suggestions:${RES}" >&2
            echo -e "${YELLOW_COLOR}1. Run this script with sudo or as root user${RES}" >&2
            echo -e "${YELLOW_COLOR}2. Check file permissions in target directories${RES}" >&2
            echo -e "${YELLOW_COLOR}3. Ensure your user has write access to $BIN_PATH and $CONFIG_PATH${RES}" >&2
            ;;
        "security")
            echo -e "${YELLOW_COLOR}Recovery suggestions:${RES}" >&2
            echo -e "${YELLOW_COLOR}1. Download the file manually and verify its integrity${RES}" >&2
            echo -e "${YELLOW_COLOR}2. Check if the download was interrupted${RES}" >&2
            echo -e "${YELLOW_COLOR}3. Verify you're downloading from the official source${RES}" >&2
            echo -e "${YELLOW_COLOR}4. Report the issue to EasyTier maintainers${RES}" >&2
            ;;
        "system")
            echo -e "${YELLOW_COLOR}Recovery suggestions:${RES}" >&2
            echo -e "${YELLOW_COLOR}1. Ensure your system meets the requirements${RES}" >&2
            echo -e "${YELLOW_COLOR}2. Check available disk space${RES}" >&2
            echo -e "${YELLOW_COLOR}3. Verify required tools are installed (curl, unzip)${RES}" >&2
            echo -e "${YELLOW_COLOR}4. Check system logs for related errors${RES}" >&2
            ;;
        *)
            echo -e "${YELLOW_COLOR}Recovery suggestions:${RES}" >&2
            [ -n "$recovery_suggestion" ] && echo -e "${YELLOW_COLOR}$recovery_suggestion${RES}" >&2
            echo -e "${YELLOW_COLOR}1. Check the error message above for details${RES}" >&2
            echo -e "${YELLOW_COLOR}2. Try running with --no-gh-proxy if using GitHub proxy${RES}" >&2
            echo -e "${YELLOW_COLOR}3. For more help, visit: https://github.com/EasyTier/EasyTier${RES}" >&2
            ;;
    esac
    
    echo -e "${YELLOW_COLOR}If the problem persists, please create an issue at:${RES}" >&2
    echo -e "${BLUE_COLOR}https://github.com/EasyTier/EasyTier/issues${RES}" >&2
    echo -e "\r\n${RED_COLOR}Installation failed.${RES}\r\n" >&2
}

# Download and verify SHA256 checksums file
download_and_verify_checksums() {
    local checksum_url="$1"
    local binary_dir="$2"
    
    # Download checksums file
    local checksum_file="${TMP_DIR}/checksums.txt"
    echo -e "${BLUE_COLOR}Downloading checksums file...${RES}"
    if ! curl -sSL "$checksum_url" -o "$checksum_file"; then
        echo -e "${YELLOW_COLOR}Warning: Failed to download checksums file, skipping verification${RES}" >&2
        return 0
    fi
    
    # Verify checksums for each binary file
    local verification_failed=false
    
    for binary in "easytier-core" "easytier-cli" "easytier-web" "easytier-web-embed"; do
        local binary_path="${binary_dir}/${binary}"
        if [ -f "$binary_path" ]; then
            # Extract expected checksum for this binary
            local expected_checksum=$(grep "${binary}$" "$checksum_file" | cut -d' ' -f1)
            
            if [ -n "$expected_checksum" ]; then
                if ! verify_sha256_checksum "$binary_path" "$expected_checksum"; then
                    verification_failed=true
                    echo -e "${RED_COLOR}Error: Checksum verification failed for $binary${RES}" >&2
                fi
            else
                echo -e "${YELLOW_COLOR}Warning: No checksum found for $binary${RES}" >&2
            fi
        fi
    done
    
    rm -f "$checksum_file"
    
    if $verification_failed; then
        return 1
    fi
    
    echo -e "${GREEN_COLOR}All checksums verified successfully${RES}"
    return 0
}

CHECK() {
  if [ -f "$BIN_PATH/easytier-core" ] || [ -d "$CONFIG_PATH" ]; then
    echo "EasyTier seems to be already installed. Please use 'update' or 'uninstall'." >&2
    exit 1
  fi
}

INSTALL() {
  # Add retry mechanism for API request
  local retry_count=0
  local max_retries=3
  local RESPONSE=""
  
  while [ $retry_count -lt $max_retries ]; do
    RESPONSE=$(curl -s "https://api.github.com/repos/EasyTier/EasyTier/releases/latest")
    LATEST_VERSION=$(echo "$RESPONSE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | tr -d '[:space:]')
    
    if [ -n "$LATEST_VERSION" ]; then
      break
    fi
    
    retry_count=$((retry_count + 1))
    if [ $retry_count -lt $max_retries ]; then
      echo -e "${YELLOW_COLOR}Retry $retry_count/$max_retries: Failed to get latest version, retrying in 2 seconds...${RES}" >&2
      sleep 2
    fi
  done
  
  if [ -z "$LATEST_VERSION" ]; then 
    handle_error "Failed to get latest version after $max_retries attempts" "This might be due to GitHub API rate limits or network issues. Try again later or use --no-gh-proxy." "network"
    exit 1; 
  fi

  local DL_OS=$OS && if [ "$DL_OS" = "darwin" ]; then DL_OS="macos"; fi
  echo -e "\r\n${GREEN_COLOR}Downloading EasyTier $LATEST_VERSION ...${RES}"
  TMP_DIR="/tmp/easytier_install" && rm -rf $TMP_DIR && mkdir -p $TMP_DIR
  BASE_URL="https://github.com/EasyTier/EasyTier/releases/latest/download/easytier-${DL_OS}-${ARCH}-${LATEST_VERSION}.zip"
  DOWNLOAD_URL=$($NO_GH_PROXY && echo "$BASE_URL" || echo "${GH_PROXY}${BASE_URL}")
  echo -e "Download URL: ${GREEN_COLOR}${DOWNLOAD_URL}${RES}"
  
  # Add retry mechanism for download
  local download_retry=0
  local download_max_retries=3
  local download_success=false
  
  while [ $download_retry -lt $download_max_retries ]; do
    if curl -sSL ${DOWNLOAD_URL} -o $TMP_DIR/easytier.zip; then
      echo -e "${GREEN_COLOR}Download complete.${RES}"
      download_success=true
      break
    else
      download_retry=$((download_retry + 1))
      if [ $download_retry -lt $download_max_retries ]; then
        echo -e "${YELLOW_COLOR}Download attempt $download_retry/$download_max_retries failed, retrying in 3 seconds...${RES}" >&2
        sleep 3
      fi
    fi
  done
  
  if ! $download_success; then
    handle_error "Download failed after $download_max_retries attempts" "The download URL was: $DOWNLOAD_URL. You can try downloading manually or check your network connection." "network"
    exit 1
  fi

  echo -e "\r\n${GREEN_COLOR}Installing files...${RES}"
  unzip -o $TMP_DIR/easytier.zip -d $TMP_DIR/
  mkdir -p $BIN_PATH
  # Only create config directory if using config file mode
  if ! $W_FLAG && ! $CONFIG_SERVER_FLAG; then
    mkdir -p $CONFIG_PATH
  fi
  
  # Install all binaries
  mv $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-core $BIN_PATH/
  mv $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-cli $BIN_PATH/
  if [ -f $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-web ]; then
    mv $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-web $BIN_PATH/
  fi
  if [ -f $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-web-embed ]; then
    mv $TMP_DIR/easytier-${DL_OS}-${ARCH}/easytier-web-embed $BIN_PATH/
  fi
  
  # Set execute permissions for specific binaries
  if [ -f "$BIN_PATH/easytier-core" ]; then chmod +x "$BIN_PATH/easytier-core"; fi
  if [ -f "$BIN_PATH/easytier-cli" ]; then chmod +x "$BIN_PATH/easytier-cli"; fi
  if [ -f "$BIN_PATH/easytier-web" ]; then chmod +x "$BIN_PATH/easytier-web"; fi
  if [ -f "$BIN_PATH/easytier-web-embed" ]; then chmod +x "$BIN_PATH/easytier-web-embed"; fi
  if [ ! -f $BIN_PATH/easytier-core ]; then echo "Installation failed!" >&2; exit 1; fi
  
  # Perform SHA256 checksum verification
  echo -e "${BLUE_COLOR}Performing SHA256 checksum verification...${RES}"
  local checksum_url="https://github.com/EasyTier/EasyTier/releases/latest/download/SHA256SUMS"
  if ! download_and_verify_checksums "$checksum_url" "$TMP_DIR/easytier-${DL_OS}-${ARCH}"; then
    handle_error "SHA256 checksum verification failed" "The downloaded files may be corrupted. Please try downloading again or report this issue to EasyTier maintainers." "security"
    rm -f "$BIN_PATH/easytier-core"
    if [ -f "$BIN_PATH/easytier-cli" ]; then rm -f "$BIN_PATH/easytier-cli"; fi
    if [ -f "$BIN_PATH/easytier-web" ]; then rm -f "$BIN_PATH/easytier-web"; fi
    if [ -f "$BIN_PATH/easytier-web-embed" ]; then rm -f "$BIN_PATH/easytier-web-embed"; fi
    rm -rf $TMP_DIR
    exit 1
  fi
  
  
  rm -rf $TMP_DIR
}

INIT() {
  if [ ! -f "$BIN_PATH/easytier-core" ]; then 
      handle_error "Binary not found!" "The easytier-core binary was not found in $BIN_PATH. This could indicate an incomplete installation or incorrect permissions." "permission"
      exit 1
  fi

  # Create default config only in default config file mode
  if ! $W_FLAG && ! $C_FLAG && ! $CONFIG_SERVER_FLAG && [ ! -f "$CONFIG_PATH/default.conf" ]; then
    echo "Creating default config file..."
    cat >$CONFIG_PATH/default.conf <<EOF
instance_name = "default"
dhcp = true
listeners = ["tcp://0.0.0.0:11010", "udp://0.0.0.0:11010"]
[[peer]]
uri = "tcp://public.easytier.top:11010"
[network_identity]
network_name = "default"
network_secret = "default"
EOF
  fi

  # --- Service File Generation ---
  if [ "$INIT_SYSTEM" = "launchd" ]; then
    if $W_FLAG; then
      # Argument Mode -> Create plist with direct arguments
      cat >/Library/LaunchDaemons/com.easytier.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.easytier</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_PATH}/easytier-core</string>
$(for arg in "${ARG_MODE_ARGS[@]}"; do echo "        <string>$(escape_string "$arg")</string>"; done)
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/tmp</string>
    <key>StandardOutPath</key>
    <string>/var/log/easytier.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/easytier.log</string>
</dict>
</plist>
EOF
    elif $CONFIG_SERVER_FLAG; then
      # Config Server Mode -> Create plist with config server
      local escaped_config_server=$(escape_string "$CONFIG_SERVER_URL")
      local machine_id_args=""
      for arg in "${ARG_MODE_ARGS[@]}"; do
        if [[ "$arg" == "--machine-id" ]]; then
          machine_id_args="$machine_id_args        <string>$(escape_string "$arg")</string>"$'\n'
        elif [[ "$machine_id_args" != "" && "$arg" != "--machine-id" ]]; then
          machine_id_args="$machine_id_args        <string>$(escape_string "$arg")</string>"$'\n'
          break
        fi
      done
      
      cat >/Library/LaunchDaemons/com.easytier.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.easytier</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_PATH}/easytier-core</string>
        <string>--config-server</string>
        <string>$escaped_config_server</string>
${machine_id_args%$'\n'}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/tmp</string>
    <key>StandardOutPath</key>
    <string>/var/log/easytier.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/easytier.log</string>
</dict>
</plist>
EOF
    else
      # Config File Mode -> Create plist with config file
      local conf_path=${CONFIG_FILE_MODE_PATH:-$CONFIG_PATH/default.conf}
      local escaped_conf_path=$(escape_string "$conf_path")
      local escaped_config_path=$(escape_string "$CONFIG_PATH")
      
      cat >/Library/LaunchDaemons/com.easytier.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.easytier</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BIN_PATH}/easytier-core</string>
        <string>-c</string>
        <string>$escaped_conf_path</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>$escaped_config_path</string>
    <key>StandardOutPath</key>
    <string>/var/log/easytier.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/easytier.log</string>
</dict>
</plist>
EOF
    fi
    launchctl load /Library/LaunchDaemons/com.easytier.plist 2>/dev/null || true
    launchctl start com.easytier 2>/dev/null || true

  elif [ "$INIT_SYSTEM" = "systemd" ]; then
    if $W_FLAG; then
      # Argument Mode -> Create a single service file
      # Build safe ExecStart line with proper escaping
      local exec_start_line="${BIN_PATH}/easytier-core"
      for arg in "${ARG_MODE_ARGS[@]}"; do
          exec_start_line="$exec_start_line $(escape_string "$arg")"
      done
      
      cat >/etc/systemd/system/easytier.service <<EOF
[Unit]
Description=EasyTier Service
Wants=network.target
After=network.target
[Service]
Type=simple
WorkingDirectory=/tmp
ExecStart=$exec_start_line
Restart=always
RestartSec=1s
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload && systemctl enable easytier && systemctl start easytier
    elif $CONFIG_SERVER_FLAG; then
      # Config Server Mode -> Create a single service file
      local escaped_config_server=$(escape_string "$CONFIG_SERVER_URL")
      local exec_start_line="${BIN_PATH}/easytier-core --config-server $escaped_config_server"
      
      # Add machine-id if specified
      for arg in "${ARG_MODE_ARGS[@]}"; do
        if [[ "$arg" == "--machine-id" ]]; then
          exec_start_line="$exec_start_line $(escape_string "$arg")"
        elif [[ "$exec_start_line" == *"--machine-id"* && "$arg" != "--machine-id" ]]; then
          exec_start_line="$exec_start_line $(escape_string "$arg")"
          break
        fi
      done
      
      cat >/etc/systemd/system/easytier.service <<EOF
[Unit]
Description=EasyTier Service (Config Server Mode)
Wants=network.target
After=network.target
[Service]
Type=simple
WorkingDirectory=/tmp
ExecStart=$exec_start_line
Restart=always
RestartSec=1s
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload && systemctl enable easytier && systemctl start easytier
    else
      # Config File Mode -> Create a template service file
      local conf_path=${CONFIG_FILE_MODE_PATH:-${CONFIG_PATH}/%i.conf}
      local escaped_conf_path=$(escape_string "$conf_path")
      local escaped_config_path=$(escape_string "$CONFIG_PATH")
      
      cat >/etc/systemd/system/easytier@.service <<EOF
[Unit]
Description=EasyTier Service for %i
Wants=network.target
After=network.target
[Service]
Type=simple
WorkingDirectory=$escaped_config_path
ExecStart=${BIN_PATH}/easytier-core -c $escaped_conf_path
Restart=always
RestartSec=1s
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      if ! $C_FLAG; then # Start default instance if no specific config was given
        systemctl enable easytier@default && systemctl start easytier@default
      else
        echo -e "${YELLOW_COLOR}Service template created. Please start your instance, e.g., systemctl start easytier@<instance_name>${RES}"
      fi
    fi
  elif [ "$INIT_SYSTEM" = "openrc" ]; then
    if $W_FLAG; then
      # Argument Mode -> Create init script with direct arguments
      local escaped_bin_path=$(escape_string "$BIN_PATH")
      local escaped_args=""
      for arg in "${ARG_MODE_ARGS[@]}"; do
        escaped_args="$escaped_args $(escape_string "$arg")"
      done
      
      cat >/etc/init.d/easytier <<EOF
#!/sbin/openrc-run

name="EasyTier Service"
description="EasyTier VPN Service"
command="$escaped_bin_path/easytier-core"
command_args="$escaped_args"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
depend() {
    need net
    after firewall
}
EOF
      chmod +x /etc/init.d/easytier
      rc-update add easytier default
      rc-service easytier start
    elif $CONFIG_SERVER_FLAG; then
      # Config Server Mode -> Create init script with config server
      local escaped_bin_path=$(escape_string "$BIN_PATH")
      local escaped_config_server=$(escape_string "$CONFIG_SERVER_URL")
      local escaped_args="--config-server $escaped_config_server"
      
      # Add machine-id if specified
      for arg in "${ARG_MODE_ARGS[@]}"; do
        if [[ "$arg" == "--machine-id" ]]; then
          escaped_args="$escaped_args $(escape_string "$arg")"
        elif [[ "$escaped_args" == *"--machine-id"* && "$arg" != "--machine-id" ]]; then
          escaped_args="$escaped_args $(escape_string "$arg")"
          break
        fi
      done
      
      cat >/etc/init.d/easytier <<EOF
#!/sbin/openrc-run

name="EasyTier Service (Config Server Mode)"
description="EasyTier VPN Service"
command="$escaped_bin_path/easytier-core"
command_args="$escaped_args"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
depend() {
    need net
    after firewall
}
EOF
      chmod +x /etc/init.d/easytier
      rc-update add easytier default
      rc-service easytier start
    else
      # Config File Mode -> Create init script template
      local conf_path=${CONFIG_FILE_MODE_PATH:-${CONFIG_PATH}/\${RC_SVCNAME}.conf}
      local escaped_conf_path=$(escape_string "$conf_path")
      local escaped_config_path=$(escape_string "$CONFIG_PATH")
      local escaped_bin_path=$(escape_string "$BIN_PATH")
      
      cat >/etc/init.d/easytier <<EOF
#!/sbin/openrc-run

name="EasyTier Service for \${RC_SVCNAME}"
description="EasyTier VPN Service"
command="$escaped_bin_path/easytier-core"
command_args="-c $escaped_conf_path"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
depend() {
    need net
    after firewall
}

# Load configuration file if it exists
if [ -f "$escaped_conf_path" ]; then
    . "$escaped_conf_path"
fi
EOF
      chmod +x /etc/init.d/easytier
      rc-update add easytier default
      if ! $C_FLAG; then # Start default instance if no specific config was given
        rc-service easytier start
      else
        echo -e "${YELLOW_COLOR}Service template created. Please start your instance, e.g., rc-service easytier start${RES}"
      fi
    fi
  fi
}

SUCCESS() {
  echo -e "\r\n${GREEN_COLOR}EasyTier was installed successfully!${RES}"
  echo -e "Binaries installed to: ${GREEN_COLOR}${BIN_PATH}${RES}"
  
  # Display configuration mode
  if $CONFIG_SERVER_FLAG; then
    echo -e "Configuration mode: ${GREEN_COLOR}Config Server${RES}"
    echo -e "Config server: ${GREEN_COLOR}${CONFIG_SERVER_URL}${RES}"
  elif $W_FLAG; then
    echo -e "Configuration mode: ${GREEN_COLOR}Direct Arguments${RES}"
  elif $C_FLAG; then
    echo -e "Configuration mode: ${GREEN_COLOR}Custom Config File${RES}"
    echo -e "Config file: ${GREEN_COLOR}${CONFIG_FILE_MODE_PATH}${RES}"
  else
    echo -e "Configuration mode: ${GREEN_COLOR}Default Config File${RES}"
    echo -e "Config directory: ${GREEN_COLOR}${CONFIG_PATH}${RES}"
  fi
  echo
  if [ "$INIT_SYSTEM" = "launchd" ]; then
    echo -e "Service management commands:"
    echo -e "  Status: ${GREEN_COLOR}sudo launchctl list | grep easytier${RES}"
    echo -e "  Stop:   ${GREEN_COLOR}sudo launchctl unload /Library/LaunchDaemons/com.easytier.plist${RES}"
    echo -e "  Start:  ${GREEN_COLOR}sudo launchctl load /Library/LaunchDaemons/com.easytier.plist${RES}"
    echo -e "  Logs:   ${GREEN_COLOR}tail -f /var/log/easytier.log${RES}"
  elif [ "$INIT_SYSTEM" = "systemd" ]; then
    if $W_FLAG || $CONFIG_SERVER_FLAG; then
      echo -e "Service management commands:"
      echo -e "  Status: ${GREEN_COLOR}systemctl status easytier${RES}"
      echo -e "  Stop:   ${GREEN_COLOR}systemctl stop easytier${RES}"
      echo -e "  Start:  ${GREEN_COLOR}systemctl start easytier${RES}"
      echo -e "  Logs:   ${GREEN_COLOR}journalctl -u easytier -f${RES}"
    else
      echo -e "Service management commands (template service):"
      echo -e "  Status: ${GREEN_COLOR}systemctl status easytier@default${RES}"
      echo -e "  Stop:   ${GREEN_COLOR}systemctl stop easytier@default${RES}"
      echo -e "  Start:  ${GREEN_COLOR}systemctl start easytier@default${RES}"
      echo -e "  Logs:   ${GREEN_COLOR}journalctl -u easytier@default -f${RES}"
    fi
  elif [ "$INIT_SYSTEM" = "openrc" ]; then
    echo -e "Service management commands:"
    echo -e "  Status: ${GREEN_COLOR}rc-service easytier status${RES}"
    echo -e "  Stop:   ${GREEN_COLOR}rc-service easytier stop${RES}"
    echo -e "  Start:  ${GREEN_COLOR}rc-service easytier start${RES}"
    echo -e "  Enable: ${GREEN_COLOR}rc-update add easytier default${RES}"
    echo -e "  Disable:${GREEN_COLOR}rc-update del easytier default${RES}"
  fi
  echo
  echo -e "Default network: ${GREEN_COLOR}default${RES} (change in config file)"
  echo -e "Default port: ${GREEN_COLOR}11010 (TCP/UDP)${RES}"
}

UNINSTALL() {
    if [ ! -f "$BIN_PATH/easytier-core" ]; then
        echo "EasyTier not installed." >&2
        exit 1
    fi

    echo "Stopping services..."
    
    # 根据 init 系统精确停止服务（与 install 逻辑对称）
    if [ "$INIT_SYSTEM" = "launchd" ]; then
        # macOS - 与 install 的 launchd 逻辑匹配
        launchctl unload /Library/LaunchDaemons/com.easytier.plist 2>/dev/null || true
        
    elif [ "$INIT_SYSTEM" = "systemd" ]; then
        # Linux - 与 install 的 systemd 逻辑匹配
        systemctl stop easytier &>/dev/null || true
        systemctl disable easytier &>/dev/null || true
        systemctl stop 'easytier@*' &>/dev/null || true
        systemctl disable 'easytier@*' &>/dev/null || true
        
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        # OpenRC - 与 install 的 openrc 逻辑匹配
        rc-service easytier stop &>/dev/null || true
        rc-update del easytier default &>/dev/null || true
    fi

    echo "Deleting files..."
    
    # 精确删除服务文件（与 install 创建的文件对应）
    if [ "$INIT_SYSTEM" = "launchd" ]; then
        rm -f /Library/LaunchDaemons/com.easytier.plist
        
    elif [ "$INIT_SYSTEM" = "systemd" ]; then
        rm -f /etc/systemd/system/easytier.service
        rm -f /etc/systemd/system/easytier@.service
        
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rm -f /etc/init.d/easytier
    fi
    
    # 删除二进制文件（与 install 安装的文件对应）
    rm -f "$BIN_PATH/easytier-core"
    rm -f "$BIN_PATH/easytier-cli"
    rm -f "$BIN_PATH/easytier-web"
    rm -f "$BIN_PATH/easytier-web-embed"

    # 处理配置文件（与配置文件模式对称）
    if [ -d "$CONFIG_PATH" ]; then
        read -p "Do you want to remove the config directory $CONFIG_PATH? [y/N]: " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            rm -rf "$CONFIG_PATH"
        fi
    fi

    # 系统清理（与 install 逻辑对称）
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload &>/dev/null
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        # OpenRC doesn't need daemon-reload equivalent
        true
    fi
    
    # 验证卸载
    if [ -f "$BIN_PATH/easytier-core" ] || [ -f "/etc/systemd/system/easytier.service" ] || [ -f "/Library/LaunchDaemons/com.easytier.plist" ] || [ -f "/etc/init.d/easytier" ]; then
        echo -e "\r\n${RED_COLOR}Warning: Some files may not have been removed.${RES}"
    else
        echo -e "\r\n${GREEN_COLOR}EasyTier was removed successfully!${RES}"
    fi
}

UPDATE() {
    if [ ! -f "$BIN_PATH/easytier-core" ]; then
        echo "EasyTier not installed." >&2
        exit 1
    fi

    # 获取当前版本信息
    local CURRENT_VERSION=""
    CURRENT_VERSION=$($BIN_PATH/easytier-core --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    # 添加 v 前缀以匹配 LATEST_VERSION 格式
    if [ -n "$CURRENT_VERSION" ]; then
        CURRENT_VERSION="v$CURRENT_VERSION"
    fi
    
    # 获取最新版本信息
    local LATEST_VERSION=""
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/EasyTier/EasyTier/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | tr -d '[:space:]')
    
    if [ -z "$LATEST_VERSION" ]; then
        echo "Failed to get latest version. Please check your network connection." >&2
        exit 1
    fi

    # 版本对比检查
    if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        echo "EasyTier is already at the latest version: $CURRENT_VERSION"
        return 0
    fi

    echo "Current version: $CURRENT_VERSION, Latest version: $LATEST_VERSION"
    echo "Starting update..."

    # 创建备份
    local BACKUP_DIR="/tmp/easytier_backup_$(date +%s)"
    mkdir -p "$BACKUP_DIR"
    cp "$BIN_PATH/easytier-core" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$BIN_PATH/easytier-cli" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$BIN_PATH/easytier-web" "$BACKUP_DIR/" 2>/dev/null || true
    cp "$BIN_PATH/easytier-web-embed" "$BACKUP_DIR/" 2>/dev/null || true

    # 根据 init 系统精确停止服务（与 install/uninstall 对称）
    echo "Stopping services..."
    
    if [ "$INIT_SYSTEM" = "launchd" ]; then
        # macOS - 与 install 的 launchd 逻辑匹配
        launchctl unload /Library/LaunchDaemons/com.easytier.plist 2>/dev/null || true
        
    elif [ "$INIT_SYSTEM" = "systemd" ]; then
        # Linux - 与 install 的 systemd 逻辑匹配
        systemctl stop easytier &>/dev/null || true
        systemctl stop 'easytier@*' &>/dev/null || true
        
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        # OpenRC - 与 install 的 openrc 逻辑匹配
        rc-service easytier stop &>/dev/null || true
    fi

    # 执行更新 - 复用现有 INSTALL 函数
    echo "Downloading and installing new version..."
    if INSTALL; then
        echo "Successfully installed new version."
        
        # 根据 init 系统精确重启服务（与 install 对称）
        echo "Restarting services..."
        
        if [ "$INIT_SYSTEM" = "launchd" ]; then
            # macOS - 重启 launchd 服务
            if [ -f "/Library/LaunchDaemons/com.easytier.plist" ]; then
                launchctl load /Library/LaunchDaemons/com.easytier.plist 2>/dev/null || true
            fi
            
        elif [ "$INIT_SYSTEM" = "systemd" ]; then
            # Linux - 重启 systemd 服务
            systemctl daemon-reload
            
            # 重启已启用的实例（与 install 逻辑对称）
            if [ -f "/etc/systemd/system/easytier.service" ]; then
                systemctl enable easytier 2>/dev/null || true
                systemctl start easytier 2>/dev/null || true
            fi
            
            if [ -f "/etc/systemd/system/easytier@.service" ]; then
                # 重启所有已启用的实例
                for service in $(systemctl list-unit-files --state=enabled 2>/dev/null | grep '^easytier@' | awk '{print $1}' || true); do
                    systemctl enable "$service" 2>/dev/null || true
                    systemctl start "$service" 2>/dev/null || true
                done
                
                # 如果没有特定实例，启动默认实例
                if ! systemctl list-unit-files --state=enabled 2>/dev/null | grep -q '^easytier@' && [ -f "/etc/systemd/system/easytier@.service" ]; then
                    systemctl enable easytier@default 2>/dev/null || true
                    systemctl start easytier@default 2>/dev/null || true
                fi
            fi
            
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            # OpenRC - 重启 OpenRC 服务（与 install 逻辑一致）
            if [ -f "/etc/init.d/easytier" ]; then
                rc-update add easytier default 2>/dev/null || true
                
                # 检查是否存在配置文件决定是否启动默认实例
                local DEFAULT_CONF_PATH="${CONFIG_PATH}/default.conf"
                if [ -f "$DEFAULT_CONF_PATH" ]; then
                    rc-service easytier start 2>/dev/null || true
                else
                    echo -e "${YELLOW_COLOR}Service template created. Please start your instance, e.g., rc-service easytier start${RES}"
                fi
            fi
        fi

        # 清理备份
        rm -rf "$BACKUP_DIR"
        
        # 验证更新
        local NEW_VERSION=$($BIN_PATH/easytier-core --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        # 添加 v 前缀以匹配 LATEST_VERSION 格式
        if [ -n "$NEW_VERSION" ]; then
            NEW_VERSION="v$NEW_VERSION"
        fi
        if [ "$NEW_VERSION" = "$LATEST_VERSION" ]; then
            echo -e "\r\n${GREEN_COLOR}EasyTier was updated successfully from $CURRENT_VERSION to $NEW_VERSION!${RES}"
        else
            echo -e "\r\n${YELLOW_COLOR}Update completed, but version verification failed. New version: $NEW_VERSION${RES}"
        fi
        
    else
        # 回滚机制
        echo -e "\r\n${RED_COLOR}Update failed, restoring from backup...${RES}"
        
        # 恢复备份
        cp "$BACKUP_DIR/easytier-core" "$BIN_PATH/" 2>/dev/null || true
        cp "$BACKUP_DIR/easytier-cli" "$BIN_PATH/" 2>/dev/null || true
        cp "$BACKUP_DIR/easytier-web" "$BIN_PATH/" 2>/dev/null || true
        cp "$BACKUP_DIR/easytier-web-embed" "$BIN_PATH/" 2>/dev/null || true
        
        # 恢复执行权限
        chmod +x "$BIN_PATH/easytier-core" 2>/dev/null || true
        chmod +x "$BIN_PATH/easytier-cli" 2>/dev/null || true
        chmod +x "$BIN_PATH/easytier-web" 2>/dev/null || true
        chmod +x "$BIN_PATH/easytier-web-embed" 2>/dev/null || true
        
        # 恢复服务（与 install 逻辑对称）
        if [ "$INIT_SYSTEM" = "launchd" ]; then
            if [ -f "/Library/LaunchDaemons/com.easytier.plist" ]; then
                launchctl load /Library/LaunchDaemons/com.easytier.plist 2>/dev/null || true
            fi
        elif [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl daemon-reload
            systemctl start easytier 2>/dev/null || true
            systemctl start 'easytier@*' 2>/dev/null || true
        fi
        
        rm -rf "$BACKUP_DIR"
        echo -e "\r\n${YELLOW_COLOR}Restored to previous version: $CURRENT_VERSION${RES}"
        exit 1
    fi
}

# --- Script Entry Point ---

# Show help if no arguments or help command is used
if [ $# -eq 0 ] || [ "$1" = "help" ]; then
  HELP
  exit 0
fi

# --- Self-elevate to root ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\r\n${YELLOW_COLOR}Root privileges are required. Requesting password...${RES}"
    # Check if sudo is available
    if ! command -v sudo >/dev/null 2>&1; then
        handle_error "sudo is not available" "Please run this script as root user or install sudo first." "permission"
        exit 1
    fi
    exec sudo bash "$0" "$@"
fi

main "$@"