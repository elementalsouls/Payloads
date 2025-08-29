#!/usr/bin/env bash
# hardening_audit_pro.sh — Comprehensive READ-ONLY Linux hardening auditor (colorized)
# Purpose: Flag weak configs and common misconfigurations; NO CHANGES are made.
# Usage:
#   chmod +x hardening_audit_pro.sh
#   ./hardening_audit_pro.sh | tee "audit_$(hostname)_$(date +%F).log"

set -o pipefail

# Colors & helpers
if [ -t 1 ]; then
  RED="\033[31m"; YEL="\033[33m"; GRN="\033[32m"; BLU="\033[34m"; BOLD="\033[1m"; DIM="\033[2m"; RST="\033[0m"
else
  RED=""; YEL=""; GRN=""; BLU=""; BOLD=""; DIM=""; RST=""
fi

ok(){ printf "${GRN}[OK]${RST} %s\n" "$*"; }
warn(){ printf "${YEL}[WARN]${RST} %s\n" "$*"; }
bad(){ printf "${RED}[ALERT]${RST} %s\n" "$*"; }
info(){ printf "${BLU}[INFO]${RST} %s\n" "$*"; }
headr(){ printf "\n${BOLD}== %s ==${RST}\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

PRUNE_DIRS="/proc /sys /dev /run /snap /var/lib/docker /var/lib/containers /var/lib/lxd /var/lib/flatpak /var/lib/snapd /var/lib/kubelet"
prune_args=(); for d in $PRUNE_DIRS; do prune_args+=(-path "$d" -prune -o); done

# System / OS
headr "System / OS"
uname -a 2>/dev/null
[ -r /etc/os-release ] && head -n 5 /etc/os-release

# Accounts / Auth
headr "Accounts / Auth"
[ -r /etc/passwd ] && awk -F: '($3==0){printf "* UID0: %s\n",$1} ($3>=1000){printf "  user: %s (uid=%s)\n",$1,$3}' /etc/passwd
[ -r /etc/shadow ] && stat -c "/etc/shadow -> %A %U:%G" /etc/shadow

# Sudo
headr "Sudo"
[ -r /etc/sudoers ] && stat -c "/etc/sudoers -> %A %U:%G" /etc/sudoers
[ -d /etc/sudoers.d ] && ls -l /etc/sudoers.d

# SSH
headr "SSH"
[ -r /etc/ssh/sshd_config ] && grep -E "^(PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config

# Cron
headr "Cron"
for p in /etc/cron*; do [ -e "$p" ] && ls -ld "$p"; done

# PATH
headr "PATH"
echo "$PATH"
IFS=: read -r -a P_ARR <<< "$PATH"
for D in "${P_ARR[@]}"; do [ -d "$D" ] && ls -ld "$D"; done

# SUID / SGID
headr "SUID / SGID"
find / \( "${prune_args[@]}" -false \) -o -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | head -n 20

# Capabilities
headr "Capabilities"
have getcap && getcap -r / 2>/dev/null | head -n 20

# Sysctl
headr "Sysctl key hardening"
for k in kernel.randomize_va_space fs.protected_hardlinks fs.protected_symlinks; do sysctl -n "$k" 2>/dev/null | xargs -I{} echo "$k={}" ; done

# Summary
headr "Summary"
echo "Review alerts/warnings above. Harden SSH, sudo, cron, PATH; remove risky SUID/caps; enable firewall & logging."
