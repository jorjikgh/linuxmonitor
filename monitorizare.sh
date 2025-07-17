#!/bin/bash

BASE_DIR="$(dirname "$(readlink -f "$0")")"
LOG_FILE="$BASE_DIR/monitorizare_log.csv"
ALERT_LOG="$BASE_DIR/monitorizare_alert.log"
HASH_DIR="$BASE_DIR/hashuri_initiale"
APP_NAME="firefox"

CPU_THRESHOLD=80
MEM_THRESHOLD=80
DISK_THRESHOLD=80

[ -d "$HASH_DIR" ] || mkdir -p "$HASH_DIR"

send_alert() {
    local message="$1"
    echo "$(date) ALERTĂ: $message" >> /tmp/monitorizare_debug.log
    if command -v notify-send &>/dev/null; then
        DISPLAY=:0 XAUTHORITY=/home/george/.Xauthority notify-send "Alerte sistem" "$message"
        echo "$(date) notify-send executat" >> /tmp/monitorizare_debug.log
    fi
}


calc_hash() {
    sha256sum "$1" | awk '{print $1}'
}

init_hashes() {
    for f in /etc/passwd /etc/shadow /etc/hosts; do
        if [ -r "$f" ]; then
            calc_hash "$f" > "$HASH_DIR/$(basename $f).hash"
        else
            echo "Nu pot citi $f pentru hash" >> "$ALERT_LOG"
        fi
    done
}

check_hashes() {
    for f in /etc/passwd /etc/shadow /etc/hosts; do
        if [ -r "$f" ]; then
            new_hash=$(calc_hash "$f")
            old_hash_file="$HASH_DIR/$(basename $f).hash"
            if [ ! -f "$old_hash_file" ]; then
                send_alert "$f: hash initial absent"
            else
                old_hash=$(cat "$old_hash_file")
                if [ "$new_hash" != "$old_hash" ]; then
                    send_alert "Fișierul $f a fost modificat!"
                    echo "$new_hash" > "$old_hash_file"
                fi
            fi
        else
            send_alert "Nu pot citi $f pentru verificare hash"
        fi
    done
}

get_top3_cpu() {
    ps -eo pid,comm,%cpu --sort=-%cpu | head -n 4 | tail -n 3
}

get_top3_mem() {
    ps -eo pid,comm,%mem --sort=-%mem | head -n 4 | tail -n 3
}

get_top3_disk_io() {
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        if [ -r "/proc/$pid/io" ] && [ -r "/proc/$pid/comm" ]; then
            read_bytes=$(grep "read_bytes" /proc/$pid/io 2>/dev/null | awk '{print $2}')
            write_bytes=$(grep "write_bytes" /proc/$pid/io 2>/dev/null | awk '{print $2}')
            total_io=$((read_bytes + write_bytes))
            name=$(cat /proc/$pid/comm)
            echo "$pid:$name:$total_io"
        fi
    done | sort -t: -k3 -nr | head -n 3
}

get_open_ports() {
    ss -tuln | grep LISTEN | wc -l
}

get_root_procs() {
    ps -U root -u root u | wc -l
}

get_installed_packages_count() {
    dpkg -l | grep '^ii' | wc -l
}

get_cronjobs_count() {
    cron_system=$(ls /etc/cron.* 2>/dev/null | wc -l)
    cron_user=$(crontab -l 2>/dev/null | wc -l)
    echo $((cron_system + cron_user))
}

check_app_running() {
    pgrep "$APP_NAME" >/dev/null
    if [ $? -ne 0 ]; then
        send_alert "Aplicația monitorizată ($APP_NAME) nu ruleaza!"
    fi
}

monitor() {
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # CPU
    cpu_util=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    cpu_util_int=${cpu_util%.*}
    if [ "$cpu_util_int" -gt "$CPU_THRESHOLD" ]; then
        send_alert "CPU utilizat prea mult: ${cpu_util}%"
    fi

    # Memorie
    mem_util=$(free | awk '/Mem:/ {printf("%.2f"), $3/$2 * 100}')
    mem_util_int=${mem_util%.*}
    if [ "$mem_util_int" -gt "$MEM_THRESHOLD" ]; then
        send_alert "Memorie utilizata prea mult: ${mem_util}%"
    fi

    # Disk
    disk_util=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_util" -gt "$DISK_THRESHOLD" ]; then
        send_alert "Spațiu disk utilizat prea mult: ${disk_util}%"
    fi

    # Disk I/O 
    if command -v iostat &> /dev/null; then
        disk_io=$(iostat -d 1 2 | grep sda | tail -1 | awk '{print $3+$4}')
        disk_io_int=${disk_io%.*}
        if [ "$disk_io_int" -gt 100 ]; then
            send_alert "Rata Disk I/O ridicata: ${disk_io}"
        fi
    fi

# Network
iface=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
if [ -n "$iface" ]; then
    net_rx=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
    net_tx=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)
    net_total=$((net_rx + net_tx))

    if [ "$net_total" -lt 1000 ]; then
        send_alert "Trafic retea foarte scazut pe $iface: ${net_total} bytes"
    fi
else
    send_alert "Nu s-a putut detecta interfata de retea."
fi
    # Files
    check_hashes

    # Porturi
    ports_open=$(get_open_ports)
    if [ "$ports_open" -gt 100 ]; then
        send_alert "Număr mare de porturi deschise: ${ports_open}"
    fi
#top3
top3_cpu_names=$(get_top3_cpu | awk '{print $2}' | paste -sd ',' -)
top3_mem_names=$(get_top3_mem | awk '{print $2}' | paste -sd ',' -)
top3_disk=$(get_top3_disk_io | cut -d ':' -f 2 | paste -sd ',' -)

    # Procese root
    root_procs=$(get_root_procs)
    if [ "$root_procs" -gt 100 ]; then
        send_alert "Numar mare de procese root: ${root_procs}"
    fi

    # Pachete instalate
    installed_pkgs=$(get_installed_packages_count)
    if [ -z "$PREV_PKGS" ]; then PREV_PKGS=$installed_pkgs; fi
    if [ "$installed_pkgs" -gt "$PREV_PKGS" ]; then
        send_alert "Au fost instalate pachete noi: $installed_pkgs fata de $PREV_PKGS"
        PREV_PKGS=$installed_pkgs
    fi

    # Cronjobs
    cronjobs=$(get_cronjobs_count)
    if [ -z "$PREV_CRON" ]; then PREV_CRON=$cronjobs; fi
    if [ "$cronjobs" -gt "$PREV_CRON" ]; then
        send_alert "Au fost adaugate cronjob-uri noi: $cronjobs fata de $PREV_CRON"
        PREV_CRON=$cronjobs
    fi

    # Aplicatie monitorizata
    check_app_running

    # Scriere CSV
    echo "Data:$timestamp,CPU%:$cpu_util,MEM%:$mem_util,DISK%:$disk_util,NETWORK:$net_total,PORTS:$ports_open,PROCS:$root_procs,PKGS:$installed_pkgs,CJ:$cronjobs,TOP3_CPU:$top3_cpu_names,TOP3_MEM:$top3_mem_names,TOP3_DISK:$top3_disk" >> "$LOG_FILE"


}
case "$1" in
    init)
        init_hashes
        echo "Initializare hash-uri completa."
        ;;
    run)
        while true; do
            monitor
            sleep 60
        done
        ;;
    *)
        echo "Utilizare: $0 {init|run}"
        exit 1
        ;;
esac

