#!/usr/bin/env bash

# Copyright (c) 2025 - Malcolm Debian 12 Setup Script
# Based on Malcolm_AMI_Setup.sh adapted for Debian 12

###############################################################################
# script options
set -o pipefail
shopt -s nocasematch
ENCODING="utf-8"

###############################################################################
# checks and initialization

if [[ -z "$BASH_VERSION" ]]; then
    echo "Wrong interpreter, please run \"$0\" with bash" >&2
    exit 1
fi

# Check if running on Debian (remove the strict version check)
if ! grep -q "ID=debian" /etc/os-release 2>/dev/null; then
    echo "This script is designed for Debian" >&2
    echo "Current OS:" >&2
    cat /etc/os-release | grep PRETTY_NAME >&2
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

###############################################################################
# command-line parameters
VERBOSE_FLAG=
MALCOLM_REPO=${MALCOLM_REPO:-cisagov/Malcolm}
MALCOLM_TAG=${MALCOLM_TAG:-main}
[[ -z "$MALCOLM_UID" ]] && ( [[ $EUID -eq 0 ]] && MALCOLM_UID=1000 || MALCOLM_UID="$(id -u)" )

# Hardcoded auth credentials
AUTH_USERNAME="condef"
AUTH_PASSWORD="Temp1234!!"

while getopts 'vr:t:u:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      set -x
      ;;
    r)
      MALCOLM_REPO="$OPTARG"
      ;;
    t)
      MALCOLM_TAG="$OPTARG"
      ;;
    u)
      MALCOLM_UID="$OPTARG"
      ;;
    ?)
      echo "script usage: $(basename $0) [-v (verbose)] [-r <repo>] [-t <tag>] [-u <UID>]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [[ $EUID -eq 0 ]]; then
    SUDO_CMD=""
else
    SUDO_CMD="sudo"
fi

$SUDO_CMD mkdir -p /etc/sudoers.d/
echo 'Defaults umask = 0022' | ($SUDO_CMD su -c 'EDITOR="tee" visudo -f /etc/sudoers.d/99-default-umask')
echo 'Defaults umask_override' | ($SUDO_CMD su -c 'EDITOR="tee -a" visudo -f /etc/sudoers.d/99-default-umask')
$SUDO_CMD chmod 440 /etc/sudoers.d/99-default-umask
umask 0022

MALCOLM_USER="$(id -nu $MALCOLM_UID)"
MALCOLM_USER_GROUP="$(id -gn $MALCOLM_UID)"
MALCOLM_USER_HOME="$(getent passwd "$MALCOLM_USER" | cut -d: -f6)"
MALCOLM_URL="https://codeload.github.com/$MALCOLM_REPO/tar.gz/$MALCOLM_TAG"
LINUX_CPU=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
IMAGE_ARCH_SUFFIX="$(uname -m | sed 's/^x86_64$//' | sed 's/^arm64$/-arm64/' | sed 's/^aarch64$/-arm64/')"

# Generate password hashes for auth_setup
AUTH_PASSWORD_OPENSSL=$(openssl passwd -1 "$AUTH_PASSWORD")
AUTH_PASSWORD_HTPASSWD=$(htpasswd -nbB "$AUTH_USERNAME" "$AUTH_PASSWORD" | cut -d: -f2)

echo "Setting up Malcolm on Debian..."
echo "User: $MALCOLM_USER ($MALCOLM_UID)"
echo "Home: $MALCOLM_USER_HOME"
echo "Auth Username: $AUTH_USERNAME"

###################################################################################
# InstallEssentialPackages - adapted for Debian
function InstallEssentialPackages {
    echo "Installing essential packages..." >&2

    $SUDO_CMD apt-get update
    $SUDO_CMD DEBIAN_FRONTEND=noninteractive apt-get install -y \
        cron \
        curl \
        dialog \
        git \
        apache2-utils \
        jq \
        make \
        openssl \
        tmux \
        xz-utils \
        ca-certificates \
        gnupg \
        lsb-release
}

################################################################################
# InstallPythonPackages - adapted for Debian 12
function InstallPythonPackages {
    echo "Installing Python 3 and pip packages..." >&2

    $SUDO_CMD DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        python3-yaml \
        python3-requests

    # For Debian 12, install packages with --break-system-packages
    $SUDO_CMD python3 -m pip install --break-system-packages \
        dateparser==1.2.1 \
        kubernetes==32.0.1 \
        python-dotenv==1.1.0 \
        pythondialog==3.5.3 \
        ruamel.yaml==0.18.15
}

################################################################################
# InstallDocker - adapted for Debian
function InstallDocker {
    echo "Installing Docker and docker-compose..." >&2

    # install docker, if needed
    if ! command -v docker >/dev/null 2>&1 ; then
        # Add Docker's official GPG key
        $SUDO_CMD mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | $SUDO_CMD gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        $(lsb_release -cs) stable" | $SUDO_CMD tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        $SUDO_CMD apt-get update
        $SUDO_CMD DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin

        $SUDO_CMD systemctl enable docker
        $SUDO_CMD systemctl start docker

        if [[ -n "$MALCOLM_USER" ]]; then
            echo "Adding \"$MALCOLM_USER\" to group \"docker\"..." >&2
            $SUDO_CMD usermod -a -G docker "$MALCOLM_USER"
            echo "$MALCOLM_USER will need to log out and log back in for this to take effect" >&2
        fi

    else
        echo "\"docker\" is already installed!" >&2
    fi # docker install check

    # install docker-compose, if needed
    if ! command -v docker-compose >/dev/null 2>&1 ; then
        echo "Installing Docker Compose via curl to /usr/local/bin..." >&2

        $SUDO_CMD curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        $SUDO_CMD chmod 755 /usr/local/bin/docker-compose
        if ! /usr/local/bin/docker-compose version >/dev/null 2>&1 ; then
            echo "Installing docker-compose failed" >&2
            exit 1
        fi
    else
        echo "\"docker-compose\" is already installed!" >&2
    fi # docker-compose install check
}

################################################################################
# SystemConfig - adapted for Debian
function SystemConfig {
    echo "Configuring system settings..." >&2

    if [[ -d /etc/sysctl.d ]] && ! grep -q swappiness /etc/sysctl.d/*.conf 2>/dev/null; then

        $SUDO_CMD tee -a /etc/sysctl.d/99-sysctl-performance.conf > /dev/null <<'EOT'

# allow dmg reading
kernel.dmesg_restrict=0

# the maximum number of open file handles
fs.file-max=518144

# the maximum number of user inotify watches
fs.inotify.max_user_watches=131072

# the maximum number of memory map areas a process may have
vm.max_map_count=262144

# the maximum number of incoming connections
net.core.somaxconn=65535

# decrease "swappiness" (swapping out runtime memory vs. dropping pages)
vm.swappiness=1

# the % of system memory fillable with "dirty" pages before flushing
vm.dirty_background_ratio=40

# maximum % of dirty system memory before committing everything
vm.dirty_ratio=80
EOT
    fi # sysctl check

    if [[ ! -f /etc/security/limits.d/limits.conf ]]; then
        $SUDO_CMD mkdir -p /etc/security/limits.d/
        $SUDO_CMD tee /etc/security/limits.d/limits.conf > /dev/null <<'EOT'
* soft nofile 65535
* hard nofile 65535
* soft memlock unlimited
* hard memlock unlimited
* soft nproc 262144
* hard nproc 524288
* soft core 0
* hard core 0
EOT
    fi # limits.conf check

    # Adapted grub config for Debian
    if [[ -f /etc/default/grub ]] && ! grep -q cgroup /etc/default/grub; then
        $SUDO_CMD sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*/& systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem random.trust_cpu=on preempt=voluntary/' /etc/default/grub
        $SUDO_CMD update-grub  # Debian uses update-grub instead of grub2-mkconfig
    fi # grub check
}

###################################################################################
# _GitLatestRelease - query the latest version from a github project's releases
function _GitLatestRelease {
  if [[ -n "$1" ]]; then
    (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases/latest" | jq '.tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      (set -o pipefail && curl -sL -f "https://api.github.com/repos/$1/releases" | jq '.[0].tag_name' | sed -e 's/^"//' -e 's/"$//' ) || \
      echo unknown
  else
    echo "unknown">&2
  fi
}

################################################################################
# _InstallYQ - install yq YAML processor
function _InstallYQ {
  if ! command -v yq >/dev/null 2>&1 ; then
    YQ_RELEASE="$(_GitLatestRelease mikefarah/yq)"
    if [[ "$LINUX_CPU" == "arm64" ]]; then
      YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_arm64"
    elif [[ "$LINUX_CPU" == "amd64" ]]; then
      YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_RELEASE}/yq_linux_amd64"
    else
      YQ_URL=
    fi
    if [[ -n "$YQ_URL" ]]; then
      $SUDO_CMD curl -sSL -o /usr/local/bin/yq "$YQ_URL"
      $SUDO_CMD chmod 755 /usr/local/bin/yq
      $SUDO_CMD chown root:root /usr/local/bin/yq
    fi
  fi
}

################################################################################
# InstallUserLocalBinaries - install various tools
function InstallUserLocalBinaries {
    _InstallYQ
}

################################################################################
# InstallMalcolm - clone and configure Malcolm
function InstallMalcolm {
    echo "Downloading and unpacking Malcolm..." >&2

    pushd "$MALCOLM_USER_HOME" >/dev/null 2>&1
    
    # Remove existing Malcolm directory if it exists
    if [[ -d ./Malcolm ]]; then
        rm -rf ./Malcolm
    fi
    
    mkdir -p ./Malcolm
    curl -fsSL "$MALCOLM_URL" | tar xzf - -C ./Malcolm --strip-components 1
    
    if [[ -s ./Malcolm/docker-compose.yml ]]; then
        pushd ./Malcolm >/dev/null 2>&1
        
        # Copy example configurations
        for ENVEXAMPLE in ./config/*.example; do 
            ENVFILE="${ENVEXAMPLE%.*}"
            cp "$ENVEXAMPLE" "$ENVFILE"
        done
        
        # Update docker-compose.yml for architecture if needed
        if [[ -n "$IMAGE_ARCH_SUFFIX" ]]; then
            sed -i "s@\(/malcolm/.*\):\(.*\)@\1:\2${IMAGE_ARCH_SUFFIX}@g" docker-compose.yml
        fi
        
        echo "Pulling Docker images..." >&2
        if [[ $EUID -eq 0 ]]; then
            su - "$MALCOLM_USER" -c "cd $MALCOLM_USER_HOME/Malcolm && docker compose --profile malcolm pull"
        else
            docker compose --profile malcolm pull
        fi
        
        popd >/dev/null 2>&1
    fi
    popd >/dev/null 2>&1

    $SUDO_CMD chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME"
}
################################################################################
# ConfigureLiveCapture - enable live packet capture
function ConfigureLiveCapture {
    echo "Configuring live packet capture..." >&2
    
    # Get the correct Malcolm path dynamically
    MALCOLM_PATH="$HOME/Malcolm"
    
    # Get primary network interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        PRIMARY_INTERFACE="eth0"
    fi
    
    echo "Configuring live capture on interface: $PRIMARY_INTERFACE"
    echo "Working in directory: $MALCOLM_PATH"
    
    # Configure pcap-capture.env for live capture
    if [[ -f "$MALCOLM_PATH/config/pcap-capture.env" ]]; then
        sed -i '/^PCAP_ENABLE_TCPDUMP=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ENABLE_NETSNIFF=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_IFACE=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_IFACE_TWEAK=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ROTATE_MEGABYTES=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ROTATE_MINUTES=/d' "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_FILTER=/d' "$MALCOLM_PATH/config/pcap-capture.env"


        echo "PCAP_ENABLE_TCPDUMP=false" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_ENABLE_NETSNIFF=true" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_IFACE=$PRIMARY_INTERFACE" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_IFACE_TWEAK=false" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_ROTATE_MEGABYTES=4096" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_ROTATE_MINUTES=0" >> "$MALCOLM_PATH/config/pcap-capture.env"
        echo "PCAP_FILTER=" >> "$MALCOLM_PATH/config/pcap-capture.env"

        echo "Configured pcap-capture.env"
    else
        echo "pcap-capture.env not found at $MALCOLM_PATH/config/pcap-capture.env"
    fi

    
    echo "Live capture configured on interface: $PRIMARY_INTERFACE"
}
# SetupAuthentication - using Malcolm-Test approach
function SetupAuthentication {
    echo "Setting up Malcolm authentication using non-interactive auth_setup..." >&2
    
    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1
    
    # Use Malcolm-Test's non-interactive auth_setup approach
    echo "Running auth_setup with Malcolm-Test parameters..."
    if [[ $EUID -eq 0 ]]; then
        su - "$MALCOLM_USER" -c "
            cd $MALCOLM_USER_HOME/Malcolm && 
            python3 ./scripts/auth_setup \
                --auth-noninteractive \
                --auth-method basic \
                --auth-admin-username '$AUTH_USERNAME' \
                --auth-admin-password-openssl '$AUTH_PASSWORD_OPENSSL' \
                --auth-admin-password-htpasswd '$AUTH_PASSWORD_HTPASSWD' \
                --auth-generate-webcerts \
                --auth-generate-fwcerts \
                --auth-generate-netbox-passwords \
                --auth-generate-redis-password \
                --auth-generate-postgres-password \
                --auth-generate-keycloak-db-password \
                --auth-generate-opensearch-internal-creds || true"
    else
        python3 ./scripts/auth_setup \
            --auth-noninteractive \
            --auth-method basic \
            --auth-admin-username "$AUTH_USERNAME" \
            --auth-admin-password-openssl "$AUTH_PASSWORD_OPENSSL" \
            --auth-admin-password-htpasswd "$AUTH_PASSWORD_HTPASSWD" \
            --auth-generate-webcerts \
            --auth-generate-fwcerts \
            --auth-generate-netbox-passwords \
            --auth-generate-redis-password \
            --auth-generate-postgres-password \
            --auth-generate-keycloak-db-password \
            --auth-generate-opensearch-internal-creds || true
    fi
    
    popd >/dev/null 2>&1
}

################################################################################
# StartMalcolm
function StartMalcolm {
    echo "Starting Malcolm..." >&2
    
    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1
    
    if [[ $EUID -eq 0 ]]; then
        su - "$MALCOLM_USER" -c "cd $MALCOLM_USER_HOME/Malcolm && docker compose --profile malcolm up -d"
    else
        docker compose --profile malcolm up -d
    fi
    
    popd >/dev/null 2>&1
}

################################################################################
# "main"

SystemConfig
InstallEssentialPackages
InstallUserLocalBinaries
InstallPythonPackages
InstallDocker
InstallMalcolm
ConfigureLiveCapture
SetupAuthentication



echo ""
echo "================================================================"
echo "Malcolm installation completed successfully!"
echo "================================================================"
echo "Web interface: https://$(hostname -I | awk '{print $1}')/"
echo "Username: $AUTH_USERNAME"
echo "Password: $AUTH_PASSWORD"
echo ""
echo "Management commands:"
echo "  cd $MALCOLM_USER_HOME/Malcolm"
echo "  docker compose --profile malcolm up -d      # Start"
echo "  docker compose --profile malcolm down       # Stop"
echo "  docker compose --profile malcolm restart    # Restart"
echo "  docker compose --profile malcolm logs       # Logs"
echo ""
echo "Note: Malcolm may take 5-10 minutes to fully start up"
echo "================================================================"
