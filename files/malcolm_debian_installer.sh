#!/usr/bin/env bash

###############################################################################
# Malcolm installer for Debian 12 (bookworm) and Debian 13 (trixie)
# Based on Malcolm_AMI_Setup.sh, adapted for Debian.
#
# Tracks the LATEST Malcolm: MALCOLM_TAG defaults to "main".
#
# Fixes vs. the original malcolm_debian12_installer.sh:
#   1. Provisions Python >= 3.12 into a venv at /opt/malcolm-python.
#      Malcolm's scripts/ wrappers (auth_setup, start, stop, restart, status,
#      logs, wipe, configure, netbox-backup, netbox-restore) are ALL symlinks
#      to control.py, whose shebang is "#!/usr/bin/env python3". Since commit
#      954daf7 (2026-07-16) control.py uses a PEP 701 multi-line f-string,
#      which is Python 3.12+ only. Debian 12 ships Python 3.11 -> every one of
#      those scripts dies with:
#        SyntaxError: unterminated string literal (detected at line 1433)
#      Fixing only the auth_setup invocation is NOT enough; ./scripts/start
#      would fail identically at runtime.
#   2. Adds a compileall pre-flight so that the next time upstream raises its
#      minimum Python version, you get a one-line diagnosis instead of a
#      SyntaxError halfway through the install.
#   3. Password hashes are now generated AFTER apache2-utils is installed.
#      In the original they were computed at line 86-87, before
#      InstallEssentialPackages ran, so on a fresh box htpasswd did not exist
#      yet and AUTH_PASSWORD_HTPASSWD was silently EMPTY.
#   4. openssl passwd -1 (MD5-crypt) -> -6 (SHA-512), per Malcolm's
#      docs/authsetup.md, which specifies "openssl -passwd -6".
#   5. Removed "|| true" from auth_setup so a failure stops the install
#      instead of leaving a half-configured Malcolm.
#   6. ConfigureLiveCapture used "$HOME/Malcolm", which is /root/Malcolm when
#      run under sudo -> it silently configured nothing. Now uses
#      $MALCOLM_USER_HOME/Malcolm.
#   7. Malcolm download failure now aborts instead of being ignored.
#   8. Docker socket access is verified before attempting an image pull.
#
# Usage: ./malcolm_debian_installer.sh [-v] [-r <repo>] [-t <tag>] [-u <UID>]
#   -v            verbose (set -x)
#   -r <repo>     GitHub repo             (default cisagov/Malcolm)
#   -t <tag>      branch or release tag   (default main = latest)
#   -u <UID>      UID to install Malcolm for
#
# Env overrides: MALCOLM_REPO MALCOLM_TAG MALCOLM_UID MALCOLM_VENV
#                PY_MIN MALCOLM_AUTOSTART
###############################################################################

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

# Minimum Python version Malcolm's control.py requires, and where we put it.
PY_MIN=${PY_MIN:-3.12}
MALCOLM_VENV=${MALCOLM_VENV:-/opt/malcolm-python}
MALCOLM_PYTHON="$MALCOLM_VENV/bin/python3"

# Set to true to have this script bring Malcolm up at the end.
# (The original script defined StartMalcolm but never called it.)
MALCOLM_AUTOSTART=${MALCOLM_AUTOSTART:-false}

# Hardcoded auth credentials
AUTH_USERNAME="condef"
AUTH_PASSWORD="Temp1234!!"

# Populated later by GenerateAuthHashes, once apache2-utils is present.
AUTH_PASSWORD_OPENSSL=
AUTH_PASSWORD_HTPASSWD=

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

echo "Setting up Malcolm on Debian..."
echo "User: $MALCOLM_USER ($MALCOLM_UID)"
echo "Home: $MALCOLM_USER_HOME"
echo "Repo: $MALCOLM_REPO @ $MALCOLM_TAG"
echo "Auth Username: $AUTH_USERNAME"

###############################################################################
# Die - abort with a message
function Die {
    echo "" >&2
    echo "ERROR: $*" >&2
    exit 1
}

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
        lsb-release || Die "installing essential packages failed"
}

################################################################################
# GenerateAuthHashes - must run AFTER apache2-utils (htpasswd) is installed.
#
# Malcolm's docs/authsetup.md requires hashes from "openssl -passwd -6"
# (SHA-512). The original script used -1, which is MD5-crypt.
function GenerateAuthHashes {
    echo "Generating credential hashes..." >&2

    command -v openssl  >/dev/null 2>&1 || Die "openssl not found"
    command -v htpasswd >/dev/null 2>&1 || Die "htpasswd not found (install apache2-utils)"

    AUTH_PASSWORD_OPENSSL="$(openssl passwd -6 "$AUTH_PASSWORD")"
    AUTH_PASSWORD_HTPASSWD="$(htpasswd -nbB "$AUTH_USERNAME" "$AUTH_PASSWORD" | cut -d: -f2)"

    [[ -n "$AUTH_PASSWORD_OPENSSL"  ]] || Die "failed to generate openssl password hash"
    [[ -n "$AUTH_PASSWORD_HTPASSWD" ]] || Die "failed to generate htpasswd password hash"
}

################################################################################
# PythonAtLeast - $1 = interpreter, $2 = "3.12"
function PythonAtLeast {
    "$1" -c "import sys; m=tuple(map(int,'$2'.split('.'))); sys.exit(0 if sys.version_info[:2] >= m else 1)" 2>/dev/null
}

################################################################################
# ProvisionPython - make sure a Python >= $PY_MIN exists, with Malcolm's deps,
# and that Malcolm's "#!/usr/bin/env python3" scripts will resolve to it.
function ProvisionPython {
    echo "Provisioning Python >= $PY_MIN for Malcolm..." >&2

    # Idempotent: the Ludus role runs this script twice (once as root, once as
    # 'debian'), so don't tear down and rebuild a perfectly good venv on the
    # second pass.
    if [[ -x "$MALCOLM_PYTHON" ]] && PythonAtLeast "$MALCOLM_PYTHON" "$PY_MIN" && \
       "$MALCOLM_PYTHON" -c 'import yaml, requests, dotenv, dateparser, kubernetes, dialog, ruamel.yaml' 2>/dev/null; then
        echo "Reusing existing venv: $MALCOLM_PYTHON ($("$MALCOLM_PYTHON" -V 2>&1))" >&2
        return 0
    fi

    $SUDO_CMD DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-setuptools \
        python3-wheel || Die "installing python3 packages failed"

    local base="" v

    # 1. system python3 already new enough (Debian 13 / Ubuntu 24.04 / newer)
    if command -v python3 >/dev/null 2>&1 && PythonAtLeast python3 "$PY_MIN"; then
        base="$(command -v python3)"
    else
        # 2. a distro-provided versioned interpreter, if one happens to exist
        for v in 3.14 3.13 3.12; do
            if command -v "python$v" >/dev/null 2>&1 && PythonAtLeast "python$v" "$PY_MIN"; then
                base="$(command -v "python$v")"
                break
            fi
        done
    fi

    # 3. nothing new enough (this is where Debian 12 lands) -> standalone build
    if [[ -z "$base" ]]; then
        echo "No Python >= $PY_MIN found (system python3 is $(python3 -V 2>&1))." >&2
        echo "Fetching a standalone CPython $PY_MIN via uv..." >&2

        if ! command -v uv >/dev/null 2>&1; then
            curl -fsSL https://astral.sh/uv/install.sh | $SUDO_CMD env UV_INSTALL_DIR=/usr/local/bin sh || \
                Die "failed to install uv; install Python >= $PY_MIN manually or use a Debian 13 base"
        fi
        command -v uv >/dev/null 2>&1 || export PATH="/usr/local/bin:$PATH"

        $SUDO_CMD env UV_PYTHON_INSTALL_DIR=/opt/uv-python uv python install "$PY_MIN" || \
            Die "uv could not install Python $PY_MIN"
        base="$($SUDO_CMD env UV_PYTHON_INSTALL_DIR=/opt/uv-python uv python find "$PY_MIN")"

        [[ -n "$base" && -x "$base" ]] || Die "uv installed Python $PY_MIN but its path could not be resolved"
    fi

    echo "Base interpreter: $base ($("$base" -V 2>&1))" >&2

    # Build a venv at a stable path so the interpreter's own versioned
    # directory name never leaks into anything else.
    $SUDO_CMD rm -rf "$MALCOLM_VENV"
    $SUDO_CMD "$base" -m venv --copies "$MALCOLM_VENV" || Die "could not create venv at $MALCOLM_VENV"
    $SUDO_CMD "$MALCOLM_PYTHON" -m pip install --quiet --upgrade pip || Die "pip upgrade failed"

    # NOTE: a venv does not see apt's python3-yaml / python3-requests, so
    # PyYAML and requests must be installed explicitly here.
    # Left unpinned deliberately: this script tracks Malcolm's main branch,
    # so its dependencies move too.
    $SUDO_CMD "$MALCOLM_PYTHON" -m pip install --quiet \
        dateparser \
        kubernetes \
        python-dotenv \
        pythondialog \
        PyYAML \
        requests \
        ruamel.yaml || Die "installing Malcolm's Python dependencies failed"

    # Malcolm's scripts/{start,stop,auth_setup,...} are symlinks to control.py
    # with "#!/usr/bin/env python3", so the venv must be first on the Malcolm
    # user's PATH for them to work after this script exits.
    echo "export PATH=\"$MALCOLM_VENV/bin:\$PATH\"" \
        | $SUDO_CMD tee "$MALCOLM_USER_HOME/.malcolm_python_env" >/dev/null
    $SUDO_CMD chown "$MALCOLM_USER:$MALCOLM_USER_GROUP" "$MALCOLM_USER_HOME/.malcolm_python_env"

    local rc
    for rc in .profile .bashrc; do
        $SUDO_CMD touch "$MALCOLM_USER_HOME/$rc"
        $SUDO_CMD chown "$MALCOLM_USER:$MALCOLM_USER_GROUP" "$MALCOLM_USER_HOME/$rc"
        $SUDO_CMD grep -q malcolm_python_env "$MALCOLM_USER_HOME/$rc" 2>/dev/null || \
            echo ". $MALCOLM_USER_HOME/.malcolm_python_env" \
                | $SUDO_CMD tee -a "$MALCOLM_USER_HOME/$rc" >/dev/null
    done

    echo "Malcolm will use: $MALCOLM_PYTHON ($("$MALCOLM_PYTHON" -V 2>&1))" >&2
}

################################################################################
# PinMalcolmShebangs - point Malcolm's own Python scripts at the venv.
#
# REQUIRED for non-login shells. Ansible's shell module runs "/bin/sh -c",
# which sources neither ~/.profile nor ~/.bashrc, so the PATH entry written by
# ProvisionPython is invisible to a task like:
#     - name: Start Malcolm
#       ansible.builtin.shell:
#         cmd: /home/debian/Malcolm/scripts/start
#         become_user: debian
# Without this, that task resolves "#!/usr/bin/env python3" to the system
# Python 3.11 and dies with the same SyntaxError we're trying to avoid.
# Rewriting the shebang makes ./scripts/start work identically from Ansible,
# cron, systemd and interactive shells.
#
# scripts/{start,stop,restart,status,logs,wipe,auth_setup,configure,
# netbox-backup,netbox-restore} are all symlinks to control.py / install.py,
# so rewriting the .py files covers every wrapper.
#
# Scope is deliberately limited to scripts/ -- Malcolm's in-container Python
# must keep using each container's own interpreter.
function PinMalcolmShebangs {
    echo "Pinning Malcolm's script shebangs to $MALCOLM_PYTHON..." >&2

    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1 || Die "Malcolm directory missing"

    local n=0 f
    while IFS= read -r -d '' f; do
        if head -1 "$f" | grep -q '^#!.*python3\?$'; then
            # no sudo here: sed -i renames a temp file into place, which would
            # leave the result root-owned. The tree is already $MALCOLM_USER's.
            sed -i "1s|^#!.*python3\?$|#!$MALCOLM_PYTHON|" "$f" && n=$((n+1))
        fi
    done < <(find scripts/ -maxdepth 2 -name '*.py' -type f -print0)

    popd >/dev/null 2>&1

    $SUDO_CMD chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME/Malcolm"

    [[ $n -gt 0 ]] || Die "no Malcolm python scripts were pinned; layout may have changed upstream"
    echo "Pinned $n script(s)." >&2
}

################################################################################
# VerifyMalcolmPython - pre-flight: will Malcolm's sources even compile?
#
# This is the guard that turns a future upstream Python bump into a clear
# message instead of a SyntaxError mid-install.
function VerifyMalcolmPython {
    echo "Verifying Malcolm's Python sources compile under $("$MALCOLM_PYTHON" -V 2>&1)..." >&2

    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1 || Die "Malcolm directory missing"

    if ! "$MALCOLM_PYTHON" -m compileall -q scripts/ >/dev/null 2>&1; then
        echo "" >&2
        echo "Malcolm's Python sources do not compile under $("$MALCOLM_PYTHON" -V 2>&1)." >&2
        echo "Upstream has most likely raised its minimum Python version." >&2
        echo "Re-run with a higher floor, e.g.:  PY_MIN=3.13 $0" >&2
        echo "" >&2
        "$MALCOLM_PYTHON" -m compileall -q scripts/ 2>&1 | head -20 >&2
        popd >/dev/null 2>&1
        exit 1
    fi

    # compileall leaves __pycache__ behind; keep the tree tidy and user-owned
    find scripts/ -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null

    popd >/dev/null 2>&1
    echo "Malcolm's Python sources compile cleanly." >&2
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
            docker-compose-plugin || Die "installing docker failed"

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
# _DockerUsable - can the account that will run compose actually reach the socket?
#
# When this script is run non-root, the freshly-added "docker" group is not yet
# active in the current session, so the pull would fail with a permission error.
function _DockerUsable {
    if [[ $EUID -eq 0 ]]; then
        su - "$MALCOLM_USER" -c "docker info" >/dev/null 2>&1
    else
        docker info >/dev/null 2>&1
    fi
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
# InstallMalcolm - download, unpack and pull Malcolm
function InstallMalcolm {
    echo "Downloading and unpacking Malcolm ($MALCOLM_REPO @ $MALCOLM_TAG)..." >&2

    pushd "$MALCOLM_USER_HOME" >/dev/null 2>&1 || Die "cannot cd to $MALCOLM_USER_HOME"

    # Remove existing Malcolm directory if it exists
    if [[ -d ./Malcolm ]]; then
        rm -rf ./Malcolm
    fi

    mkdir -p ./Malcolm
    curl -fsSL "$MALCOLM_URL" | tar xzf - -C ./Malcolm --strip-components 1 || \
        Die "downloading Malcolm from $MALCOLM_URL failed"

    [[ -s ./Malcolm/docker-compose.yml ]] || \
        Die "Malcolm download looks incomplete (no docker-compose.yml); check MALCOLM_REPO/MALCOLM_TAG"

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

    popd >/dev/null 2>&1
    popd >/dev/null 2>&1

    $SUDO_CMD chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME"
}

################################################################################
# PullMalcolmImages - separated out so the Python pre-flight can run first
# (no point pulling several GB of images if auth_setup is going to fail).
function PullMalcolmImages {
    echo "Pulling Docker images..." >&2

    if ! _DockerUsable; then
        echo "" >&2
        echo "Cannot reach the Docker socket as $MALCOLM_USER." >&2
        echo "If this script was just run non-root, the new 'docker' group is not" >&2
        echo "active in this shell yet. Log out and back in (or run: newgrp docker)" >&2
        echo "and re-run this script." >&2
        Die "docker not usable"
    fi

    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1 || Die "Malcolm directory missing"

    if [[ $EUID -eq 0 ]]; then
        su - "$MALCOLM_USER" -c "cd $MALCOLM_USER_HOME/Malcolm && docker compose --profile malcolm pull" || \
            Die "docker compose pull failed"
    else
        docker compose --profile malcolm pull || Die "docker compose pull failed"
    fi

    popd >/dev/null 2>&1
}

################################################################################
# ConfigureLiveCapture - enable live packet capture
function ConfigureLiveCapture {
    echo "Configuring live packet capture..." >&2

    # NOTE: the original used "$HOME/Malcolm", which is /root/Malcolm under
    # sudo, so this function silently did nothing.
    MALCOLM_PATH="$MALCOLM_USER_HOME/Malcolm"

    # Get primary network interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        PRIMARY_INTERFACE="eth0"
    fi

    echo "Configuring live capture on interface: $PRIMARY_INTERFACE"
    echo "Working in directory: $MALCOLM_PATH"

    # Configure pcap-capture.env for live capture
    if [[ -f "$MALCOLM_PATH/config/pcap-capture.env" ]]; then
        sed -i '/^PCAP_ENABLE_TCPDUMP=/d'    "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ENABLE_NETSNIFF=/d'   "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_IFACE=/d'             "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_IFACE_TWEAK=/d'       "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ROTATE_MEGABYTES=/d'  "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_ROTATE_MINUTES=/d'    "$MALCOLM_PATH/config/pcap-capture.env"
        sed -i '/^PCAP_FILTER=/d'            "$MALCOLM_PATH/config/pcap-capture.env"

        {
            echo "PCAP_ENABLE_TCPDUMP=false"
            echo "PCAP_ENABLE_NETSNIFF=true"
            echo "PCAP_IFACE=$PRIMARY_INTERFACE"
            echo "PCAP_IFACE_TWEAK=false"
            echo "PCAP_ROTATE_MEGABYTES=4096"
            echo "PCAP_ROTATE_MINUTES=0"
            echo "PCAP_FILTER="
        } >> "$MALCOLM_PATH/config/pcap-capture.env"

        echo "Configured pcap-capture.env"
    else
        echo "pcap-capture.env not found at $MALCOLM_PATH/config/pcap-capture.env" >&2
    fi

    echo "Live capture configured on interface: $PRIMARY_INTERFACE"
}

################################################################################
# SetupAuthentication - non-interactive auth_setup (Malcolm-Test style)
function SetupAuthentication {
    echo "Setting up Malcolm authentication using non-interactive auth_setup..." >&2

    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1 || Die "Malcolm directory missing"

    # control.py uses parser.parse_args() (strict), so ONE unrecognized flag
    # makes argparse exit 2 before generating anything at all -- not even the
    # secrets whose flags are still valid.
    #
    # This bit us already: Malcolm renamed Redis to Valkey, so
    # --auth-generate-redis-password became --auth-generate-valkey-password.
    # Since this script tracks main, ask auth_setup which flags it actually
    # supports and pass only those. A future rename then costs one skipped
    # secret and a loud warning instead of a dead install.
    local auth_help
    auth_help="$("$MALCOLM_PYTHON" ./scripts/auth_setup --help 2>&1)" || \
        Die "could not run 'auth_setup --help'; Malcolm or its Python env is broken"

    local -a auth_args=(
        --auth-noninteractive
        --auth-method basic
        --auth-admin-username    "$AUTH_USERNAME"
        --auth-admin-password-openssl  "$AUTH_PASSWORD_OPENSSL"
        --auth-admin-password-htpasswd "$AUTH_PASSWORD_HTPASSWD"
    )

    # Optional generators. Both spellings of the Valkey/Redis flag are listed;
    # whichever this Malcolm build understands is the one that gets used.
    local -a want_flags=(
        --auth-generate-webcerts
        --auth-generate-fwcerts
        --auth-generate-netbox-passwords
        --auth-generate-valkey-password
        --auth-generate-redis-password
        --auth-generate-postgres-password
        --auth-generate-keycloak-db-password
        --auth-generate-opensearch-internal-creds
    )

    local flag
    local -a skipped=()
    for flag in "${want_flags[@]}"; do
        if grep -q -- "$flag" <<<"$auth_help"; then
            auth_args+=("$flag")
        else
            skipped+=("$flag")
        fi
    done

    if [[ ${#skipped[@]} -gt 0 ]]; then
        echo "NOTE: this Malcolm build does not support: ${skipped[*]}" >&2
        echo "      (expected for the Redis/Valkey rename; investigate anything else)" >&2
    fi

    # Sanity check: if the admin flags themselves have gone, stop now rather
    # than configuring a Malcolm with no administrator.
    grep -q -- '--auth-admin-password-htpasswd' <<<"$auth_help" || \
        Die "auth_setup no longer accepts --auth-admin-password-htpasswd; flag set has changed upstream"

    # $MALCOLM_PYTHON is an absolute path into the venv, so this does not
    # depend on PATH being set up for whatever shell we happen to be in.
    echo "Running auth_setup..." >&2
    if [[ $EUID -eq 0 ]]; then
        # printf %q makes the hashes (which contain '$') safe to hand to su -c
        local quoted
        quoted="$(printf '%q ' "$MALCOLM_PYTHON" ./scripts/auth_setup "${auth_args[@]}")"
        su - "$MALCOLM_USER" -c "cd '$MALCOLM_USER_HOME/Malcolm' && $quoted" || \
            Die "auth_setup failed"
    else
        "$MALCOLM_PYTHON" ./scripts/auth_setup "${auth_args[@]}" || Die "auth_setup failed"
    fi

    popd >/dev/null 2>&1

    $SUDO_CMD chown -R $MALCOLM_USER:$MALCOLM_USER_GROUP "$MALCOLM_USER_HOME/Malcolm"
    echo "Authentication configured." >&2
}

################################################################################
# StartMalcolm
function StartMalcolm {
    echo "Starting Malcolm..." >&2

    pushd "$MALCOLM_USER_HOME/Malcolm" >/dev/null 2>&1 || Die "Malcolm directory missing"

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
GenerateAuthHashes
InstallUserLocalBinaries
ProvisionPython
InstallDocker
InstallMalcolm
PinMalcolmShebangs
VerifyMalcolmPython
PullMalcolmImages
ConfigureLiveCapture
SetupAuthentication

if [[ "$MALCOLM_AUTOSTART" == "true" ]]; then
    StartMalcolm
fi

echo ""
echo "================================================================"
echo "Malcolm installation completed successfully!"
echo "================================================================"
echo "Malcolm version: $MALCOLM_REPO @ $MALCOLM_TAG"
echo "Python:          $("$MALCOLM_PYTHON" -V 2>&1) ($MALCOLM_PYTHON)"
echo "Web interface:   https://$(hostname -I | awk '{print $1}')/"
echo "Username:        $AUTH_USERNAME"
echo "Password:        $AUTH_PASSWORD"
echo ""
if [[ "$MALCOLM_AUTOSTART" != "true" ]]; then
    echo "Malcolm was NOT started. To start it:"
else
    echo "Malcolm is starting. Management commands:"
fi
echo "  cd $MALCOLM_USER_HOME/Malcolm"
echo "  ./scripts/start                             # Start (recommended)"
echo "  ./scripts/stop                              # Stop"
echo "  ./scripts/restart                           # Restart"
echo "  ./scripts/logs                              # Logs"
echo "  ./scripts/status                            # Status"
echo ""
echo "Those scripts have had their shebangs pinned to $MALCOLM_PYTHON,"
echo "so they work from Ansible, cron, systemd and interactive shells alike."
echo "$MALCOLM_VENV/bin was also added to $MALCOLM_USER's PATH"
echo "via ~/.malcolm_python_env for interactive use."
echo ""
echo "Note: Malcolm may take 5-10 minutes to fully start up"
echo "================================================================"
