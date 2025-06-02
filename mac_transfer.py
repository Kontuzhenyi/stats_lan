import sqlite3
import nmap
from datetime import datetime, timedelta
import logging
import os
import time
import sys
from threading import Thread

# Настройка логирования для journald
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%I:%M:%S %p',  # 12-часовой формат с AM/PM
    handlers=[
        logging.StreamHandler(sys.stdout)  # Вывод в stdout для journald
    ]
)

DB_FILE = "/home/viktor/stats_lan/network_test.db"
CHECK_INTERVAL = 30  # Интервал проверки в секундах
TRANSFER_DELAY = timedelta(minutes=10)  # Задержка перед переносом (2 часа)

def get_mac_for_ip(ip):
    """Определяет MAC-адрес для IP с помощью nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sn', sudo=True)
        if ip in nm.all_hosts() and nm[ip].state() == 'up':
            return nm[ip]['addresses'].get('mac', 'N/A')
        return 'N/A'
    except Exception as e:
        logging.error(f"Ошибка определения MAC для {ip}: {e}")
        return 'N/A'

def transfer_to_main_table(conn, ip, mac, rx, tx, current_month):
    """Переносит данные в основную таблицу traffic_<YYYYMM>."""
    table_name = f"traffic_{current_month}2"
    cursor = conn.cursor()
    
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT,
            rx INTEGER,
            tx INTEGER
        )
    ''')

    cursor.execute(f'''
        SELECT rx, tx FROM {table_name} WHERE ip = ? AND mac = ?
    ''', (ip, mac))
    result = cursor.fetchone()
    if result:
        current_rx, current_tx = result
        new_rx = current_rx + rx
        new_tx = current_tx + tx
        cursor.execute(f'''
            UPDATE {table_name}
            SET rx = ?, tx = ?
            WHERE ip = ?
        ''', (new_rx, new_tx, ip))
    else:
        cursor.execute(f'''
            INSERT INTO {table_name} (ip, mac, rx, tx)
            VALUES (?, ?, ?, ?)
        ''', (ip, mac, rx, tx))
    logging.info(f"Перенесена запись в {table_name}: ip={ip}, mac={mac}, rx={rx}, tx={tx}")

def process_records():
    """Обрабатывает записи во временной таблице."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    current_month = datetime.now().strftime("%Y%m")
    cursor.execute('SELECT * FROM temp_traffic')
    records = cursor.fetchall()

    for record in records:
        record_id, ip, rx, tx, mac, timestamp = record
        if mac is None:
            # Определяем MAC в отдельном потоке для ускорения
            # def update_mac():
            #     new_mac = get_mac_for_ip(ip)
            #     with sqlite3.connect(DB_FILE) as conn_inner:
            #         cursor_inner = conn_inner.cursor()
            #         cursor_inner.execute('''
            #             UPDATE temp_traffic
            #             SET mac = ?, timestamp = ?
            #             WHERE id = ?
            #         ''', (new_mac, datetime.now(), record_id))
            #         conn_inner.commit()
            #         logging.info(f"Определён MAC для ip={ip}: {new_mac}")
            # Thread(target=update_mac).start()
            new_mac = get_mac_for_ip(ip)
            cursor.execute('''
                UPDATE temp_traffic
                SET mac = ?, timestamp = ?
                WHERE id = ?
            ''', (new_mac, datetime.now(), record_id))
            logging.info(f"Определён MAC для ip={ip}: {new_mac}")

        elif timestamp:
            record_time = datetime.fromisoformat(timestamp)
            if datetime.now() - record_time >= TRANSFER_DELAY:
                transfer_to_main_table(conn, ip, mac, rx, tx, current_month)
                cursor.execute('DELETE FROM temp_traffic WHERE id = ?', (record_id,))
                logging.info(f"Удалена обработанная запись из temp_traffic: id={record_id}")

    conn.commit()
    conn.close()

def main():
    """Основная функция сервиса: периодическая проверка и обработка."""  
    logging.info("Сервис определения MAC и переноса данных в основную таблицу запущен.")
    while True:
        process_records()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()