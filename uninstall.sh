#!/bin/sh

set -eu
set -f

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
active_venv=${WIFITE_UNINSTALL_VENV:-${VIRTUAL_ENV:-}}
poetry_env=${WIFITE_UNINSTALL_POETRY_ENV:-}
status=0
newline='
'
python_paths=''
installs=''
pacman_packages=''
rpm_packages=''
cleanup_paths=''
cleanup_keys=''
protected_outputs=''
found_output_paths=''
found_handshakes=0
found_cracked_results=0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[36m'
    C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'
else
    C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''
fi

if [ "$#" -gt 0 ]; then
    printf '%s\n' 'Run this uninstaller without arguments.' >&2
    exit 2
fi

add_python_path() {
    candidate_python=$1
    [ -x "$candidate_python" ] || return 0
    case "$newline$python_paths$newline" in *"$newline$candidate_python$newline"*) return 0 ;; esac
    python_paths="${python_paths}${python_paths:+$newline}$candidate_python"
}

record_install() { installs="${installs}${installs:+$newline}$1"; }

add_cleanup_path() {
    candidate_path=$1
    [ -e "$candidate_path" ] || [ -L "$candidate_path" ] || return 0
    normalized_path=$candidate_path
    if command -v realpath >/dev/null 2>&1; then
        normalized_path=$(realpath -m -- "$candidate_path" 2>/dev/null || printf '%s' "$candidate_path")
    fi
    case "$normalized_path" in
        /|/home|/root|/tmp|/var/tmp|/usr|/usr/local|/opt|"${HOME:-/root}")
            printf 'Refusing to remove a broad system or home path: %s\n' "$candidate_path" >&2
            return 1
            ;;
    esac
    case "$script_dir/" in
        "$normalized_path/"*)
            if [ "$normalized_path" != "$script_dir" ]; then
                printf 'Refusing to remove a parent of the uninstaller checkout: %s\n' "$candidate_path" >&2
                return 1
            fi
            ;;
    esac
    # Never add the checkout itself as a cleanup target.
    [ "$normalized_path" != "$script_dir" ] || return 0
    case "$newline$cleanup_keys$newline" in *"$newline$normalized_path$newline"*) return 0 ;; esac
    saved_cleanup_ifs=$IFS
    IFS=$newline
    for existing_cleanup in $cleanup_keys; do
        case "$normalized_path" in
            "$existing_cleanup"/*)
                IFS=$saved_cleanup_ifs
                return 0
                ;;
        esac
    done
    IFS=$saved_cleanup_ifs
    cleanup_keys="${cleanup_keys}${cleanup_keys:+$newline}$normalized_path"
    cleanup_paths="${cleanup_paths}${cleanup_paths:+$newline}$candidate_path"
}

add_generated_output() {
    generated_path=$1
    [ -e "$generated_path" ] || [ -L "$generated_path" ] || return 0
    generated_dir=${generated_path%/*}
    generated_name=${generated_path##*/}
    if command -v git >/dev/null 2>&1 &&
       git -C "$generated_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
       git -C "$generated_dir" ls-files --error-unmatch -- "$generated_name" >/dev/null 2>&1; then
        return 0
    fi
    add_cleanup_path "$generated_path"
}

launcher_is_package_owned() {
    check_launcher=$1
    if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -S "$check_launcher" >/dev/null 2>&1; then return 0; fi
    if command -v pacman >/dev/null 2>&1 && pacman -Qo "$check_launcher" >/dev/null 2>&1; then return 0; fi
    if command -v rpm >/dev/null 2>&1 && rpm -qf "$check_launcher" >/dev/null 2>&1; then return 0; fi
    return 1
}

add_orphan_launcher() {
    launcher=$1
    [ -e "$launcher" ] || [ -L "$launcher" ] || return 0
    launcher_is_package_owned "$launcher" && return 0
    if [ -f "$launcher" ] && grep -Eqi 'wifite2|wifite\.wifite' "$launcher"; then add_cleanup_path "$launcher"; fi
}

clear_prompt_rows() {
    rows=$1
    printf '\033[%sA' "$rows"
    row=0
    while [ "$row" -lt "$rows" ]; do
        printf '\r\033[2K'
        row=$((row + 1))
        if [ "$row" -lt "$rows" ]; then printf '\033[1B'; fi
    done
    if [ "$rows" -gt 1 ]; then printf '\033[%sA' "$((rows - 1))"; fi
    printf '\r'
}

prompt_yes_no() {
    prompt_text=$1
    retry=0
    while :; do
        if [ "$retry" -eq 1 ]; then
            if [ -t 1 ]; then
                columns=$(tput cols 2>/dev/null || printf '80')
                case "$columns" in ''|*[!0-9]*) columns=80 ;; esac
                [ "$columns" -gt 0 ] || columns=80
                prompt_length=$((${#prompt_text} + 6))
                response_length=${#answer}
                rows=$(( (prompt_length + response_length) / columns + 1 ))
                clear_prompt_rows "$rows"
                printf '%b\n' "${C_RED}Please enter y or n.${C_RESET}"
                sleep 2
                clear_prompt_rows 1
            else
                printf '%b\n' "${C_RED}Please enter y or n.${C_RESET}"
            fi
        fi
        printf '%b' "${C_CYAN}${prompt_text} [y/n] ${C_RESET}"
        if ! IFS= read -r answer; then return 2; fi
        case "$answer" in
            y|Y|yes|YES|Yes) return 0 ;;
            n|N|no|NO|No) return 1 ;;
            *) retry=1 ;;
        esac
    done
}

has_install() {
    saved_ifs=$IFS
    IFS=$newline
    for item in $installs; do
        if [ "$item" = "$1" ]; then IFS=$saved_ifs; return 0; fi
    done
    IFS=$saved_ifs
    return 1
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    elif command -v sudo >/dev/null 2>&1; then sudo -- "$@"
    else printf 'Cannot remove system item without root or sudo: %s\n' "$*" >&2; return 1
    fi
}

pip_uninstall() {
    PIP_ROOT_USER_ACTION=ignore "$python_to_uninstall" -m pip uninstall "$@"
}

sudo_pip_uninstall() {
    sudo -- env PIP_ROOT_USER_ACTION=ignore "$python_to_uninstall" -m pip uninstall "$@"
}

uninstall_python_install() {
    python_to_uninstall=$1
    if ! "$python_to_uninstall" -m pip show wifite2 >/dev/null 2>&1; then return 0; fi
    printf 'Removing pip install using %s\n' "$python_to_uninstall"

    python_stdlib=$("$python_to_uninstall" -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null || true)
    if [ -f "$python_stdlib/EXTERNALLY-MANAGED" ]; then
        # PEP 668 blocks a normal pip uninstall. Use its explicit override first
        # so users don't see the expected externally-managed error on stderr.
        if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
            if sudo_pip_uninstall -y --break-system-packages wifite2; then return 0; fi
        fi
        if pip_uninstall -y --break-system-packages wifite2; then return 0; fi
        return 1
    fi

    if pip_uninstall -y wifite2; then return 0; fi
    if pip_uninstall -y --break-system-packages wifite2; then return 0; fi
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        if sudo_pip_uninstall -y wifite2; then return 0; fi
        sudo_pip_uninstall -y --break-system-packages wifite2
        return $?
    fi
    return 1
}

if [ -z "$poetry_env" ] && command -v poetry >/dev/null 2>&1; then
    poetry_env=$(cd "$script_dir" && poetry env info --path 2>/dev/null || true)
fi
if [ -n "$active_venv" ]; then add_python_path "$active_venv/bin/python"; fi
add_python_path "$script_dir/.venv/bin/python"
add_python_path "$script_dir/venv/bin/python"
if [ -n "$poetry_env" ]; then add_python_path "$poetry_env/bin/python"; fi
if command -v python3 >/dev/null 2>&1; then add_python_path "$(command -v python3)"; fi
if command -v python >/dev/null 2>&1; then add_python_path "$(command -v python)"; fi

# Wifite is often run through sudo; remove state for both the invoking user and root.
user_home=${HOME:-}
if [ -n "${SUDO_USER:-}" ] && command -v getent >/dev/null 2>&1; then
    invoking_home=$(getent passwd "$SUDO_USER" | cut -d: -f6 || true)
    [ -z "$invoking_home" ] || user_home=$invoking_home
fi
root_home=$(getent passwd root 2>/dev/null | cut -d: -f6 || true)
[ -n "$root_home" ] || root_home=/root
passwd_homes=$(getent passwd 2>/dev/null | cut -d: -f6 || true)
home_roots="${user_home}${user_home:+$newline}${root_home}${newline}${passwd_homes}"
saved_ifs=$IFS
IFS=$newline
for state_home in $home_roots; do
    [ -n "$state_home" ] || continue
    add_cleanup_path "$state_home/.wifite"
    add_cleanup_path "$state_home/.config/wifite"
    add_cleanup_path "$state_home/.cache/wifite"
    add_cleanup_path "$state_home/.local/share/wifite"
    add_cleanup_path "$state_home/.local/state/wifite"
    add_orphan_launcher "$state_home/.local/bin/wifite"
done
IFS=$saved_ifs
for launcher in /usr/local/bin/wifite /usr/local/sbin/wifite /usr/bin/wifite /usr/sbin/wifite /bin/wifite /sbin/wifite; do
    add_orphan_launcher "$launcher"
done

find_wifite_outputs() {
    output_root=$1
    [ -d "$output_root" ] || return 0
    find "$output_root" -mindepth 1 -maxdepth 1 \
        \( \( -type d -o -type l \) -name hs -o \
           \( -type f -o -type l \) \( -name cracked.json -o -name ieee-oui.txt \
               -o -name reaver_output.pcap -o -name 'replay_*.cap' -o -name 'replay_*.xor' \
               -o -name 'attack_monitor_*.log' -o -name wifite_tui.log \
               -o -name 'wifite_hash_*.22000' -o -name 'wifite_john_*.john' \
               -o -name 'wifite_pmkids_*.22000' -o -name 'wifite_hscheck_*.22000' \
               -o -name 'handshake_*.cap' -o -name 'sae_handshake_*.cap' -o -name 'pmkid_*.22000' \) \) \
        -print 2>/dev/null || true
}

# Wifite writes normal outputs relative to its working directory. Check the
# current directory, this checkout, filesystem root, and user home directories.
output_roots="${PWD}${newline}${script_dir}${newline}/${newline}${home_roots}${newline}/sdcard${newline}/storage/emulated/0"
saved_ifs=$IFS
IFS=$newline
for output_root in $output_roots; do
    found_for_root=$(find_wifite_outputs "$output_root")
    [ -z "$found_for_root" ] || found_output_paths="${found_output_paths}${found_output_paths:+$newline}$found_for_root"
done
for output_path in $found_output_paths; do
    output_name=${output_path##*/}
    case "$output_path" in
        */.wifite|*/.config/wifite|*/.cache/wifite|*/.local/share/wifite|*/.local/state/wifite)
            add_cleanup_path "$output_path"
            ;;
        */.local/bin/wifite)
            add_orphan_launcher "$output_path"
            ;;
        *)
            case "$output_name" in
        hs|handshake_*.cap|sae_handshake_*.cap|pmkid_*.22000)
            found_handshakes=1
            case "$newline$protected_outputs$newline" in
                *"$newline$output_path$newline"*) ;;
                *) protected_outputs="${protected_outputs}${protected_outputs:+$newline}$output_path" ;;
            esac
            ;;
        cracked.json)
            found_cracked_results=1
            case "$newline$protected_outputs$newline" in
                *"$newline$output_path$newline"*) ;;
                *) protected_outputs="${protected_outputs}${protected_outputs:+$newline}$output_path" ;;
            esac
            ;;
        ieee-oui.txt|reaver_output.pcap|replay_*.cap|replay_*.xor|attack_monitor_*.log|wifite_tui.log|wifite_hash_*.22000|wifite_john_*.john|wifite_pmkids_*.22000|wifite_hscheck_*.22000)
            add_generated_output "$output_path"
            ;;
            esac
            ;;
    esac
done
IFS=$saved_ifs

for local_item in .venv venv build dist wifite2.egg-info; do add_cleanup_path "$script_dir/$local_item"; done
cache_dirs=$(find "$script_dir" -type d \( -name __pycache__ -o -name .pytest_cache \) -prune -print 2>/dev/null || true)
saved_ifs=$IFS
IFS=$newline
for cache_dir in $cache_dirs; do add_cleanup_path "$cache_dir"; done
IFS=$saved_ifs
if [ -n "$poetry_env" ]; then add_cleanup_path "$poetry_env"; fi
case "$active_venv/" in "$script_dir/"*) add_cleanup_path "$active_venv" ;; esac

tmp_roots="${TMPDIR:-}
${TEMP:-}
${TMP:-}
/tmp
/var/tmp"
saved_ifs=$IFS
IFS=$newline
for tmp_root in $tmp_roots; do
    [ -d "$tmp_root" ] || continue
    tmp_items=$(find "$tmp_root" -mindepth 1 -maxdepth 1 \
        \( -type d -name 'wifite*' -o \( -type f -o -type l \) \
           \( -name 'wifite_hash_*.22000' -o -name 'wifite_john_*.john' \
              -o -name 'wifite_pmkids_*.22000' -o -name 'wifite_hscheck_*.22000' \) \) \
        -print 2>/dev/null || true)
    for tmp_item in $tmp_items; do add_cleanup_path "$tmp_item"; done
done
IFS=$saved_ifs

saved_ifs=$IFS
IFS=$newline
for python_path in $python_paths; do
    if "$python_path" -m pip show wifite2 >/dev/null 2>&1; then record_install "pip: $python_path"; fi
done
IFS=$saved_ifs
if command -v dpkg-query >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    dpkg_status=$(dpkg-query -W -f='${db:Status-Status}' wifite 2>/dev/null || true)
    [ "$dpkg_status" != installed ] || record_install 'apt/dpkg: wifite'
fi
if command -v pacman >/dev/null 2>&1; then
    for package in wifite wifite2 wifite2-git; do
        if pacman -Qq "$package" >/dev/null 2>&1; then
            pacman_packages="${pacman_packages}${pacman_packages:+$newline}$package"
            record_install "pacman: $package"
        fi
    done
fi
if command -v rpm >/dev/null 2>&1; then
    for package in wifite wifite2; do
        if rpm -q "$package" >/dev/null 2>&1; then
            rpm_packages="${rpm_packages}${rpm_packages:+$newline}$package"
            record_install "rpm: $package"
        fi
    done
fi

if [ -z "$installs" ] && [ -z "$cleanup_paths" ] && [ -z "$protected_outputs" ]; then
    printf '%b\n' "${C_GREEN}Wifite is already clean. No installs or app data were found.${C_RESET}"
    exit 0
fi

printf '\n%b' "${C_CYAN}${C_BOLD}"
cat <<'BANNER'
╭──────────────────────────────────────────────╮
│             WIFITE CLEAN UNINSTALL            │
╰──────────────────────────────────────────────╯
BANNER
printf '%b\n\n' "$C_RESET"
if [ -n "$installs" ]; then
    printf '%b\n' "${C_BOLD}Detected installations:${C_RESET}"
    printf '%s\n' "$installs" | while IFS= read -r item; do printf '  %b•%b %s\n' "$C_GREEN" "$C_RESET" "$item"; done
fi
if [ -n "$cleanup_paths" ]; then
    printf '\n%b\n' "${C_BOLD}Wifite files scheduled for automatic cleanup (name — path):${C_RESET}"
    printf '%s\n' "$cleanup_paths" | while IFS= read -r item; do
        printf '  %b•%b %s — %s\n' "$C_YELLOW" "$C_RESET" "${item##*/}" "$item"
    done
fi
if [ -n "$protected_outputs" ]; then
    if [ "$found_handshakes" -eq 1 ] && [ "$found_cracked_results" -eq 1 ]; then
        protected_heading='Captured handshakes and cracked results found:'
        protected_delete_prompt='Delete the captured handshakes and cracked results?'
        protected_keep_message='Keeping the captured handshakes and cracked results.'
        protected_no_input='No interactive input available; keeping the captured handshakes and cracked results.'
    elif [ "$found_handshakes" -eq 1 ]; then
        protected_heading='Captured handshakes found:'
        protected_delete_prompt='Delete the captured handshakes?'
        protected_keep_message='Keeping the captured handshakes.'
        protected_no_input='No interactive input available; keeping the captured handshakes.'
    else
        protected_heading='Cracked results found:'
        protected_delete_prompt='Delete the cracked results?'
        protected_keep_message='Keeping the cracked results.'
        protected_no_input='No interactive input available; keeping the cracked results.'
    fi
    printf '\n%b\n' "${C_YELLOW}${protected_heading}${C_RESET}"
    printf '%s\n' "$protected_outputs" | while IFS= read -r item; do
        printf '  %b•%b %s — %s\n' "$C_YELLOW" "$C_RESET" "${item##*/}" "$item"
    done
    if [ ! -t 0 ]; then
        printf '%b\n' "${C_YELLOW}${protected_no_input}${C_RESET}"
    elif prompt_yes_no "$protected_delete_prompt"; then
        saved_ifs=$IFS
        IFS=$newline
        for output_path in $protected_outputs; do add_cleanup_path "$output_path"; done
        IFS=$saved_ifs
    else
        prompt_result=$?
        if [ "$prompt_result" -eq 2 ]; then
            printf '\n%b\n' "${C_YELLOW}${protected_no_input}${C_RESET}"
        else
            printf '%b\n' "${C_GREEN}${protected_keep_message}${C_RESET}"
        fi
    fi
fi

saved_ifs=$IFS
IFS=$newline
for python_path in $python_paths; do
    if has_install "pip: $python_path"; then uninstall_python_install "$python_path" || status=1; fi
done
IFS=$saved_ifs
if has_install 'apt/dpkg: wifite'; then
    printf '%s\n' 'Removing apt/dpkg package wifite'
    run_privileged apt-get remove -y wifite || status=1
fi
saved_ifs=$IFS
IFS=$newline
for package in $pacman_packages; do
    [ -n "$package" ] || continue
    printf 'Removing pacman package %s\n' "$package"
    run_privileged pacman -R --noconfirm "$package" || status=1
done
for package in $rpm_packages; do
    [ -n "$package" ] || continue
    printf 'Removing RPM package %s\n' "$package"
    if command -v dnf >/dev/null 2>&1; then run_privileged dnf remove -y "$package" || status=1
    elif command -v yum >/dev/null 2>&1; then run_privileged yum remove -y "$package" || status=1
    else printf 'No dnf or yum command is available to remove %s\n' "$package" >&2; status=1
    fi
done
IFS=$saved_ifs

saved_ifs=$IFS
IFS=$newline
for cleanup_path in $cleanup_paths; do
    [ -n "$cleanup_path" ] || continue
    printf 'Removing %s\n' "$cleanup_path"
    run_privileged rm -rf -- "$cleanup_path" || status=1
done
IFS=$saved_ifs

if [ "$status" -eq 0 ]; then
    printf '%b\n' "${C_GREEN}${C_BOLD}Wifite cleanup complete.${C_RESET}"
    printf '%s\n' 'The source checkout and shared system dependencies were left in place.'
else
    printf '%b\n' "${C_RED}Some items could not be removed. Review the errors above and retry with the required permissions.${C_RESET}" >&2
fi
exit "$status"
