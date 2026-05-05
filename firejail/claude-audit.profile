# claude-audit firejail profile
# Sandbox pour les outils SAST/secrets/IaC qui peuvent exécuter du code client malveillant.
# Bloque : .ssh / .aws / .gnupg / shadow / sudo / mining wallet
# Réseau : géré dynamiquement par client-audit-code (AUDIT_OFFLINE=1 = --net=none)
# Whitelisting : géré par CLI (--whitelist passé par le wrapper sur le snapshot et logs)

# Bloque l'accès aux secrets de Sky
blacklist ${HOME}/.ssh
blacklist ${HOME}/.aws
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.config/git
blacklist ${HOME}/.cargo/credentials
blacklist ${HOME}/.cargo/credentials.toml
blacklist ${HOME}/.npm/_auth
blacklist ${HOME}/.composer/auth.json
blacklist ${HOME}/.docker/config.json
blacklist ${HOME}/.kube/config
blacklist ${HOME}/.netrc
blacklist ${HOME}/.pgpass

# Bloque l'accès au reste de Bureau (où sont les .desktop, configs, etc.)
blacklist ${HOME}/Bureau/Audit-Securite-Clients
blacklist ${HOME}/.claude-tooling
blacklist ${HOME}/.claude
blacklist ${HOME}/.config/claude
blacklist ${HOME}/.linux-upgrade

# Anti-cryptojack : pas d'accès au wallet de mining
blacklist /opt/miners
blacklist /opt/linux-upgrade

# Bloque les secrets système
blacklist /etc/shadow
blacklist /etc/sudoers
blacklist /etc/sudoers.d
blacklist /root

# Drop privileges
noroot
nogroups
nonewprivs
seccomp
caps.drop all

# Resource limits (anti-DoS)
# rlimit-as = address space (vmem). Semgrep peut prendre >4G sur des règles complexes.
# 8 GiB = compromis raisonnable sur un Kali avec 15 GiB RAM.
rlimit-as 8589934592
rlimit-cpu 1200
rlimit-fsize 1073741824
rlimit-nproc 512
rlimit-nofile 8192

# Aucune escape via terminal/IPC
nodvd
nosound
notv
nou2f
no3d

# Pas d'IPv6 ni protocoles exotiques (le réseau est de toute façon souvent --net=none)
protocol unix,inet,inet6,netlink

# DBus-talk = no
dbus-user none
dbus-system none
