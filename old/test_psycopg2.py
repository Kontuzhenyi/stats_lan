import psycopg2

DB_CONFIG = {
    'dbname': 'network_statistics',
    'user': 'viktor',
    'password': 'CZ7F~B!r1$(6h$sY_\OC',
    'host': 'localhost',
    'port': 5432
}

try:
    conn = psycopg2.connect(**DB_CONFIG)
    print("Подключение успешно!")
    conn.close()
except Exception as e:
    print(f"Ошибка: {e}")