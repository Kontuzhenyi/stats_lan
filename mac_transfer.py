import psycopg2
import nmap
from datetime import datetime, timedelta
import logging
import os
import time
import sys

# Настройка логирования для journald
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%I:%M:%S %p',  # 12-часовой формат с AM/PM
    handlers=[
        logging.StreamHandler(sys.stdout)  # Вывод в stdout для journald
    ]
)

# Конфигурация подключения к PostgreSQL
DB_CONFIG = {
    'dbname': 'network_statistics',
    'user': 'viktor',
    'password': 'CZ7F~B!r1$(6h$sY_\OC',
    'host': 'localhost',
    'port': 5432
}

CHECK_INTERVAL = 15  # Интервал проверки в секундах
TRANSFER_DELAY = timedelta(minutes=10)  # Задержка перед переносом (2 часа)

def get_mac_for_ip(ip):
    # Определяет MAC-адрес для IP с помощью nmap
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
    # Переносит данные в основную таблицу traffic_<YYYYMM>
    table_name = f"traffic_{current_month}2"
    cursor = conn.cursor()
    
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {table_name} (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            mac TEXT,
            rx INTEGER,
            tx INTEGER,
            transfer_time TIMESTAMP WITH TIME ZONE
        )
    ''')

    cursor.execute(f'''
        SELECT rx, tx FROM {table_name} WHERE ip = %s AND mac = %s
    ''', (ip, mac))
    result = cursor.fetchone()
    if result:
        current_rx, current_tx = result
        new_rx = current_rx + rx
        new_tx = current_tx + tx
        cursor.execute(f'''
            UPDATE {table_name}
            SET rx = %s, tx = %s
            WHERE ip = %s AND mac = %s
        ''', (new_rx, new_tx, ip, mac))
    else:
        cursor.execute(f'''
            INSERT INTO {table_name} (ip, mac, rx, tx, transfer_time)
            VALUES (%s, %s, %s, %s, NOW())
        ''', (ip, mac, rx, tx))
    logging.info(f"Перенесена запись в {table_name}: ip={ip}, mac={mac}, rx={rx}, tx={tx}")

def process_records():
    # Обрабатывает записи во временной таблице
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        current_month = datetime.now().strftime("%Y%m")
        cursor.execute('''
            SELECT id, ip, rx, tx, mac, transfer_time 
            FROM temp_traffic 
            WHERE transfer_time IS NULL
        ''')
        records = cursor.fetchall()

        for record in records:
            record_id, ip, rx, tx, mac, transfer_time = record
            if mac is None: # Записывем mac и время в таблицу
                new_mac = get_mac_for_ip(ip)
                cursor.execute('''
                    UPDATE temp_traffic
                    SET mac = %s, transfer_time = NOW() + INTERVAL '30 minutes'
                    WHERE id = %s
                ''', (new_mac, record_id))
                logging.info(f"Определён MAC для ip={ip}: {new_mac}")
                conn.commit()

            if transfer_time: # Проверяет время
                if datetime.now() > transfer_time:
                    transfer_to_main_table(conn, ip, mac, rx, tx, current_month)
                    cursor.execute('DELETE FROM temp_traffic WHERE id = %s', (record_id,))
                    logging.info(f"Удалена обработанная запись из temp_traffic: id={record_id}")
                    conn.commit()

    except psycopg2.OperationalError as e: # В случае блокировки базы другими процессом
        logging.error(f"Ошибка доступа к базе данных: {e}. Повторная попытка через {CHECK_INTERVAL} секунд.")
    except Exception as e:
        logging.error(f"Неизвестная ошибка в process_records: {e}")
    finally:
        if 'conn' in locals(): # Полезная проверка на тот случай если мы не смогли подключиться к бд и тогда переменная conn не создатся
            conn.close()

def main():
    # Основная функция сервиса: периодическая проверка и обработка
    logging.info("Сервис определения MAC и переноса данных в основную таблицу запущен.")
    while True:
        process_records()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()