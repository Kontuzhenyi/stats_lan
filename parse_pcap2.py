import subprocess
import os
import time
import psycopg2
import glob
import logging
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

# Директория с pcap-файлами
PCAP_DIR = "/home/viktor/stats_lan/pcap_files"
# DB_FILE = "/home/viktor/stats_lan/network_test.db"

# Конфигурация подключения к PostgreSQL
DB_CONFIG = {
    'dbname': 'network_statistics',
    'user': 'viktor',
    'password': 'CZ7F~B!r1$(6h$sY_\OC',
    'host': 'localhost',
    'port': 5432
}

def is_file_in_use(pcap_file):
    """
    Проверяет, используется ли файл (например, записывается ли в него tcpdump).
    Возвращает True, если файл занят, и False, если доступен.
    """
    try:
        with open(pcap_file, 'rb') as f:
            size1 = os.path.getsize(pcap_file)
            time.sleep(2)  # Ждём 2 секунды
            size2 = os.path.getsize(pcap_file)
            if size1 != size2:
                return True
            return False
    except IOError:
        return True

def check_pcap_integrity(pcap_file):
    # Проверяет целостность pcap-файла с помощью tshark
    cmd = ['tshark', '-r', pcap_file]
    logging.info(f"Запускаем команду на проверку целостности: {cmd}")
    
    try:
        start_time = time.time()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        end_time = time.time()
        logging.info(f"Проверка на целостность выполнена за {end_time - start_time:.2f} секунд")
        
        if result.returncode != 0 or "Error" in result.stderr:
            logging.error(f"Файл {pcap_file} повреждён: {result.stderr}")
            return False
        return True
    
    except subprocess.TimeoutExpired:
        logging.error(f"Тайм-аут: tshark не завершился за 30 секунд для файла {pcap_file}")
        return False
    except FileNotFoundError:
        logging.error("tshark не найден. Убедитесь, что он установлен.")
        return False
    except Exception as e:
        logging.error(f"Произошла ошибка при проверке целостности {pcap_file}: {e}")
        return False

def parse_pcap(pcap_file):
    # Парсинг pcap-файла с помощью tshark
    traffic_data = {}
    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'conv,ip']
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    tshark_output = result.stdout.decode()

    count = 0
    for line in tshark_output.split('\n'):
        if count < 5:  # Пропустить первые 5 строк
            count += 1
            continue
        if line.startswith('='):
            break
        parts = line.split()
        if len(parts) < 7:  # Проверка на корректность строки
            continue
        src_ip = parts[0]
        dst_ip = parts[2]
        bytes_to_dst = int(parts[6])  # Байты от src к dst
        bytes_to_src = int(parts[4])  # Байты от dst к src
        # Учитываем трафик для локальных IP
        if src_ip.startswith('192.168.0'):
            traffic_data[src_ip] = traffic_data.get(src_ip, {'sent': 0, 'received': 0})
            traffic_data[src_ip]['sent'] += bytes_to_dst
            traffic_data[src_ip]['received'] += bytes_to_src
        if dst_ip.startswith('192.168.0'):
            traffic_data[dst_ip] = traffic_data.get(dst_ip, {'sent': 0, 'received': 0})
            traffic_data[dst_ip]['sent'] += bytes_to_src
            traffic_data[dst_ip]['received'] += bytes_to_dst
    
    return traffic_data

def process_pcap(pcap_file):
    # Записывает предварительные данные во временную таблицу
    if is_file_in_use(pcap_file):
        logging.info(f"Файл {os.path.basename(pcap_file)} ещё записывается. Пропускаем...")
        return False

    logging.info("-" * 50)  # Разделительная линия
    logging.info(f"Начало работы с {os.path.basename(pcap_file)}")  # Только имя файла

    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # Создание временной таблицы, если её нет
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temp_traffic (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            rx INTEGER,
            tx INTEGER,
            mac TEXT,
            transfer_time TIMESTAMP WITH TIME ZONE
        )
    ''')

    traffic_data = parse_pcap(pcap_file)

    if not traffic_data:
        logging.warning(f"Нет данных для обработки в файле {os.path.basename(pcap_file)}")
        os.remove(pcap_file)
        logging.info(f"Файл {os.path.basename(pcap_file)} удалён так как в нем не было данных")
        conn.close()
        return False
    
    # Подсчёт трафика для возврата
    total_rx, total_tx = 0, 0
    for ip, data in traffic_data.items():
        rx_bytes = data.get('received', 0)
        tx_bytes = data.get('sent', 0)
        total_rx += rx_bytes
        total_tx += tx_bytes
        mac = None  # MAC пока не определён

        # Проверка существования записи для этого IP
        cursor.execute('''
            SELECT rx, tx FROM temp_traffic WHERE ip = %s
        ''', (ip,))
        existing = cursor.fetchone()
        if existing:
            current_rx, current_tx = existing
            new_rx = current_rx + rx_bytes
            new_tx = current_tx + tx_bytes
            cursor.execute('''
                UPDATE temp_traffic
                SET rx = %s, tx = %s
                WHERE ip = %s
            ''', (new_rx, new_tx, ip))
        else:
            cursor.execute('''
                INSERT INTO temp_traffic (ip, rx, tx)
                VALUES (%s, %s, %s)
            ''', (ip, rx_bytes, tx_bytes))

    conn.commit()
    conn.close()
    return total_rx, total_tx

def main():
    # Основная функция парсера: отслеживает и обрабатывает pcap-файлы.
    logging.info("Парсер запущен.")

    while True:
        pcap_files = sorted(glob.glob(os.path.join(PCAP_DIR, "traffic_*.pcap")))
        if not pcap_files:
            logging.info("Нет файлов для обработки. Ожидание...")
            time.sleep(30)
            continue

        for pcap_file in pcap_files:
            result = process_pcap(pcap_file)
            if result:
                total_rx, total_tx = result
                logging.info(f"Добавленный трафик: RX={int(total_rx / 1000)} Кбайт, TX={int(total_tx / 1000)} Кбайт")
                try:
                    os.remove(pcap_file)
                    logging.info(f"Файл {os.path.basename(pcap_file)} обработан и удалён.")
                except OSError as e:
                    logging.error(f"Не удалось удалить файл {pcap_file}: {e}")

        time.sleep(15)

if __name__ == "__main__":
    main()