#!/usr/bin/env python3

import psycopg2
from datetime import datetime

# Параметры подключения
conn_params = {
    'host': 'localhost',
    'dbname': 'network_statistics',
    'user': 'viktor',
    'password': 'CZ7F~B!r1$(6h$sY_\OC',
}

def main():
    now = datetime.now()
    table_suffix = now.strftime('%Y%m')  # Только ГГГГММ
    target_table = f'traffic_{table_suffix}'

    try:
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = True
        cur = conn.cursor()

        # Создаём таблицу при необходимости
        cur.execute(f'''
            CREATE TABLE IF NOT EXISTS {target_table} (
                id SERIAL PRIMARY KEY,
                ip TEXT NOT NULL,
                mac TEXT,
                rx BIGINT,
                tx BIGINT,
                inserted_at TIMESTAMP DEFAULT NOW()
            );
        ''')

        # Переносим данные
        cur.execute(f'''
            INSERT INTO {target_table} (ip, mac, rx, tx)
            SELECT ip, mac, rx, tx FROM temp_traffic
            WHERE transfer_time <= NOW();
        ''')

        # Удаляем из временной
        cur.execute('DELETE FROM temp_traffic WHERE transfer_time <= NOW();')

        print(f"[{datetime.now()}] Данные перенесены в таблицу {target_table}")

    except Exception as e:
        print("Ошибка:", e)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
