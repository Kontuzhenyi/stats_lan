import subprocess
import os
import sys
import time
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)  # Вывод в stdout для journald
    ]
)

# Директория для сохранения pcap-файлов
PCAP_DIR = "/home/viktor/stats_lan/pcap_files"
os.makedirs(PCAP_DIR, exist_ok=True)
PCAP_PATTERN = os.path.join(PCAP_DIR, "traffic_%Y%m%d_%H%M%S.pcap")

def capture_traffic(interface='enp0s3', rotation_interval=15):
    """
    Запускает tcpdump для непрерывного захвата трафика с ротацией файлов.
    
    Args:
        interface (str): Сетевой интерфейс.
        rotation_interval (int): Интервал ротации в секундах (по умолчанию 15 секунд).
    """
    logging.info(f"Захват трафика начат. Файлы сохраняются в {PCAP_DIR}")
    # Устанавливаем временную зону для процесса tcpdump (+5 часов от UTC)
    env = os.environ.copy()
    env['TZ'] = 'UTC-5'  # Смещение +5 часов от UTC
    time.tzset()  # Применяем временную зону (для Unix-подобных систем)

    while True:
        try:
            # Запуск tcpdump с ротацией
            process = subprocess.Popen(
                ['sudo', 'tcpdump', '-i', interface, '-n', '-w', PCAP_PATTERN,
                 '-G', str(rotation_interval), '-W', '1000000000'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env
            )

            # Ждём завершения процесса или его перезапуска
            stdout, stderr = process.communicate()
            logging.info(f"Процесс tcpdump завершён. Код возврата: {process.returncode}")
            if stderr:
                logging.error(f"Ошибки tcpdump: {stderr}")
            logging.info("Перезапуск tcpdump...")

        except (KeyboardInterrupt, Exception) as e:
            logging.warning(f"Прерывание захвата трафика: {e}")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            logging.info("Захват остановлен.")
            sys.exit(0)

def main():
    try:
        capture_traffic(interface='enp0s3', rotation_interval=15)
    except Exception as e:
        logging.error(f"Произошла ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()