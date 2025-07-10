#!/bin/bash

LOG_FILE="./monitorizare_log.csv"
ALERT_LOG="/var/log/monitorizare_alert.log"
HASH_DIR="./hashuri_initiale"

mkdir -p "$HASH_DIR"

send_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ALERTA: $message" >> "$ALERT_LOG"
}

# hash fisiere
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
                echo "$f: hash inițial absent" >> "$ALERT_LOG"
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

monitor() {
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # CPU %
    cpu_util=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    cpu_util_int=${cpu_util%.*}
    if [ "$cpu_util_int" -gt 90 ]; then
        send_alert "CPU utilizat prea mult: ${cpu_util}%"
    fi

    # Memorie %
    mem_util=$(free | awk '/Mem:/ {printf("%.2f"), $3/$2 * 100}')
    mem_util_int=${mem_util%.*}
    if [ "$mem_util_int" -gt 90 ]; then
        send_alert "Memorie utilizată prea mult: ${mem_util}%"
    fi

    # Disk utilizat (exemplu root partition)
    disk_util=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_util" -gt 90 ]; then
        send_alert "Spațiu disk utilizat prea mult: ${disk_util}%"
    fi

    # Disk I/O rate (folosind iostat dacă există)
    if command -v iostat &> /dev/null; then
        disk_io=$(iostat -d 1 2 | grep sda | tail -1 | awk '{print $3+$4}')
        disk_io_int=${disk_io%.*}
        if [ "$disk_io_int" -gt 100 ]; then
            send_alert "Rată Disk I/O ridicată: ${disk_io}"
        fi
    fi

    # Rețea (Rx+Tx în bytes)
    net_rx=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0)
    net_tx=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0)
    net_total=$((net_rx + net_tx))
    # Alertă dacă rețeaua este inactivă (exemplu simplu)
    if [ "$net_total" -lt 1000 ]; then
        send_alert "Trafic rețea foarte scăzut: ${net_total} bytes"
    fi

    # Monitorizare fișiere
    check_hashes

    # Porturi deschise
    ports_open=$(get_open_ports)
    if [ "$ports_open" -gt 100 ]; then
        send_alert "Număr mare de porturi deschise: ${ports_open}"
    fi

    # Procese root
    root_procs=$(get_root_procs)
    if [ "$root_procs" -gt 100 ]; then
        send_alert "Număr mare de procese root: ${root_procs}"
    fi

    # Pachete instalate (monitorizare schimbare)
    installed_pkgs=$(get_installed_packages_count)
    if [ -z "$PREV_PKGS" ]; then PREV_PKGS=$installed_pkgs; fi
    if [ "$installed_pkgs" -gt "$PREV_PKGS" ]; then
        send_alert "Au fost instalate pachete noi: $installed_pkgs față de $PREV_PKGS"
        PREV_PKGS=$installed_pkgs
    fi

    # Cronjob-uri
    cronjobs=$(get_cronjobs_count)
    if [ -z "$PREV_CRON" ]; then PREV_CRON=$cronjobs; fi
    if [ "$cronjobs" -gt "$PREV_CRON" ]; then
        send_alert "Au fost adăugate cronjob-uri noi: $cronjobs față de $PREV_CRON"
        PREV_CRON=$cronjobs
    fi

    # Salvare date în CSV (exemplu simplificat)
    echo "$timestamp,$cpu_util,$mem_util,$disk_util,$net_total,$ports_open,$root_procs,$installed_pkgs,$cronjobs" >> "$LOG_FILE"
}

case "$1" in
    init)
        init_hashes
        echo "Init hashes done"
        ;;
    run)
        while true; do
            monitor
            sleep 60
        done
        ;;
    *)
        echo "Usage: $0 {init|run}"
        exit 1
        ;;
esac

