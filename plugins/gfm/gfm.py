#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import threading
import time
import json
import os
import sys
import socket
import re
import configparser
import fcntl 
from datetime import datetime, timedelta, timezone

# ==============================================================================
# [ КЛАСС GFM (Gorgona Failover Manager) ]
# ==============================================================================

class GFM:
    def __init__(self):
        """
        Инициализация менеджера отказоустойчивости.
        Загружает конфигурацию, определяет роль узла и подготавливает среду.
        """
        # 1. Загрузка параметров из gfm.conf
        self.load_config() 

        # 2. Внутреннее состояние системы
        self.role = "STANDBY"
        self.leader_name = None
        self.last_leader_heartbeat = time.time()
        self.last_monitor_sent = 0
        self.current_lsn = "0/0"
        self.is_running = True
        
        # 3. Флаги и блокировки
        # Используем RLock (Recursive Lock), чтобы один поток мог захватывать замок несколько раз
        # Это критически важно для предотвращения Deadlock при вызове auto_rebuild из process_message
        self.lock = threading.RLock() 
        self.rebuild_in_progress = False
        
        # 4. Подготовка системного окружения
        self.fix_etc_hosts()
        self.is_witness = self.detect_witness_mode()
        self.psk = self.load_psk_from_config()
        
        # 5. Определение начальной логической роли на основе реальности
        if self.is_witness == True:
            self.role = "WITNESS"
        else:
            try:
                # Проверяем реальное состояние локальной БД (Master или Standby)
                self.sync_role_with_db()
            except Exception as e:
                self.log("Initial DB sync failed: " + str(e))
            
        self.log("======================================================")
        self.log("--- GFM DISTRIBUTED CLUSTER MANAGER STARTING ---")
        self.log("Node Name       : " + str(self.node_name))
        self.log("Operation Mode  : " + ("WITNESS (Arbitrator)" if self.is_witness else "DATABASE NODE"))
        self.log("Initial State   : " + str(self.role))
        self.log("Election Timeout: " + str(self.election_timeout) + "s")
        self.log("Audit TTL       : " + str(self.event_ttl) + "s")
        self.log("======================================================")

        # 6. Прогрев (Warmup)
        # Читаем историю меша, чтобы не начинать выборы, если лидер уже есть
        try:
            self.warmup_mesh_state()
        except Exception as e:
            self.log("Warmup notice (it's okay for new clusters): " + str(e))

    # --------------------------------------------------------------------------
    # КОНФИГУРАЦИЯ И СИСТЕМНОЕ ОКРУЖЕНИЕ
    # --------------------------------------------------------------------------

    def load_config(self):
        """
        Загрузка параметров из файла конфигурации.
        Поддерживает передачу пути к конфигу через первый аргумент командной строки.
        """
        # 1. Определение пути к файлу конфигурации
        if len(sys.argv) > 1:
            self.config_full_path = sys.argv[1]
        else:
            self.config_full_path = "/etc/gorgona/gfm.conf"
            
        # 2. Проверяем существование файла по сохраненному пути
        if not os.path.exists(self.config_full_path):
            print(f"FATAL ERROR: Configuration file {self.config_full_path} not found!")
            sys.exit(1)

        conf = configparser.ConfigParser()
        conf.read(self.config_full_path)

        # 2. Секция [cluster]
        self.my_pub_hash = conf.get("cluster", "my_pub_hash")
        self.node_name = os.uname()[1]
        self.quorum_total_nodes = conf.getint("cluster", "quorum_total_nodes")
        # Уникальный ID кластера (например, pg_prod_5432) для изоляции логов и статусов
        self.cluster_id = conf.get("cluster", "cluster_id", fallback="default")

        # 3. Секция [postgresql] (Новая секция для мульти-инстанса)
        # Имя системной службы (например, postgresql@17-main)
        self.pg_service = conf.get("postgresql", "service_name", fallback="postgresql")
        # Версия и имя инстанса для pg_ctlcluster (например, 17 и main)
        self.pg_version = conf.get("postgresql", "pg_version", fallback="17")
        self.pg_instance_name = conf.get("postgresql", "pg_instance_name", fallback="main")
        self.pg_port = conf.get("postgresql", "port", fallback="5432")

        # 4. Секция [timings]
        self.heartbeat_interval = conf.getint("timings", "heartbeat_interval")
        self.max_missing_heartbeats = conf.getint("timings", "max_missing_heartbeats")
        self.monitor_interval = conf.getint("timings", "monitor_interval")
        
        # Специализированные значения TTL (Time To Live)
        self.heartbeat_ttl = conf.getint("timings", "heartbeat_ttl")
        self.event_ttl = conf.getint("timings", "event_ttl")
        self.default_ttl = conf.getint("timings", "default_ttl")
        
        # Динамический расчет таймаута выборов
        self.election_timeout = (self.heartbeat_interval * self.max_missing_heartbeats) + 5

        # 5. Секция [paths]
        base_dir_path = conf.get("paths", "base_dir")
        self.gorgona_bin = conf.get("paths", "gorgona_bin")
        self.psql_bin = conf.get("paths", "psql_bin")
        self.pg_ctl_bin = conf.get("paths", "pg_ctl_bin")
        self.rebuild_script = conf.get("paths", "rebuild_script")

        # 6. Производные пути к файлам и ключам
        # Ключи и конфиги лежат в базовой директории
        self.priv_key_path = os.path.join(base_dir_path, f"{self.my_pub_hash}.key")
        self.pub_key_arg = f"{self.my_pub_hash}.pub"
        self.gorgonad_conf_path = os.path.join(base_dir_path, "gorgonad.conf")
        
        # Файл статуса теперь содержит ID кластера, чтобы несколько GFM не затирали друг друга
        self.status_json_path = os.path.join(base_dir_path, f"status_{self.cluster_id}.json")

    def log(self, msg):
        now = datetime.now()
        timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
        # Добавляем ID кластера в каждую строку лога
        print(f"[{timestamp}] [{self.cluster_id}] [{self.role}] {msg}", flush=True)

    def safe_db_query(self, query):
        """
        Безопасное выполнение SQL с защитой от наслоения (flock) 
        и жестким тайм-аутом.
        """
        lock_file_path = f"/tmp/gfm_db_query_{self.cluster_id}.lock" 
        
        try:
            # Открываем (или создаем) файл блокировки
            with open(lock_file_path, 'w') as f:
                # Пытаемся захватить эксклюзивную блокировку без ожидания (LOCK_NB)
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    # Если файл уже заблокирован другим процессом GFM - выходим
                    # self.log("Database query skipped: previous query still running.")
                    return None

                # Выполняем команду с системным тайм-аутом (команда timeout из coreutils)
                # Это защитит, если даже psql зависнет на сетевом сокете
                cmd = [
                    "timeout", "3s", 
                    "sudo", "-u", "postgres", self.psql_bin, 
                    "-p", str(self.pg_port), 
                    "-At", "-c", query
                ]
                
                result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                return result

        except subprocess.CalledProcessError:
            # Ошибка выполнения (база лежит или таймаут)
            return None
        except Exception as e:
            self.log(f"Query error: {e}")
            return None

    def fix_etc_hosts(self):
        """Оптимизация /etc/hosts для ускорения работы sudo команд внутри GFM"""
        try:
            with open("/etc/hosts", "r") as f:
                content = f.read()
            if self.node_name not in content:
                self.log("Optimizing local hostname resolution in /etc/hosts...")
                with open("/etc/hosts", "a") as f:
                    f.write("\n127.0.0.1 " + self.node_name + "\n")
        except Exception as e:
            self.log("Warning: Could not update /etc/hosts: " + str(e))

    def detect_witness_mode(self):
        """Определяет, является ли узел Witness-нодой (отсутствие локальной БД)"""
        if os.path.exists(self.psql_bin) == False:
            return True
        try:
            # Проверяем наличие пользователя postgres в системе
            import pwd
            pwd.getpwnam('postgres')
            return False
        except KeyError:
            return True

    def load_psk_from_config(self):
        """Загружает sync_psk из конфигурации сервера для внутренних статус-запросов"""
        try:
            config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
            config.read(self.gorgonad_conf_path)
            for section in config.sections():
                if 'sync_psk' in config[section]:
                    return config[section]['sync_psk'].strip()
        except Exception:
            pass
        return None

    # --------------------------------------------------------------------------
    # МЕТОДЫ РАБОТЫ С POSTGRESQL
    # --------------------------------------------------------------------------

    def sync_role_with_db(self):
        if self.is_witness or self.rebuild_in_progress:
            return

        res = self.safe_db_query("SELECT pg_is_in_recovery();")
        
        if res is None:
            # База не отвечает - считаем, что мы в режиме ожидания (безопаснее)
            if self.role == "LEADER":
                self.log("Postgres UNREACHABLE. Possible crash?")
                self.role = "STANDBY"
            return

        if res == "f":
            self.role = "LEADER"
        else:
            self.role = "STANDBY"

    def is_replication_active(self):
        """Проверяет, реально ли узел получает WAL логи от Мастера"""
        if self.is_witness == True:
            return True
        # Если мы сами лидер, репликация "активна" по определению
        if self.role != "STANDBY":
            return True
            
        try:
            # Проверяем наличие строки в таблице wal_receiver
            cmd = ["sudo", "-u", "postgres", self.psql_bin, "-p", str(self.pg_port), "-At", "-c", "SELECT count(*) FROM pg_stat_wal_receiver;"] 
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            # Возвращает True если процесс приема запущен
            return int(res) > 0
        except Exception:
            return False
        
    def get_replication_status(self):
        """Краткий статус репликации для MONITOR-телеметрии"""
        if self.is_witness:
            return "n/a"
        if self.role == "LEADER":
            try:
                cmd = ["sudo", "-u", "postgres", self.psql_bin, "-p", str(self.pg_port), "-At", "-c",
                       "SELECT count(*) FROM pg_stat_replication;"]
                res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                return "replicas:" + str(int(res))
            except Exception:
                return "replicas:?"
        # STANDBY / CANDIDATE
        if self.lsn_to_int(self.current_lsn) == 0:
            return "empty"
        if self.is_replication_active():
            return "streaming"
        return "not_streaming"

    def get_pg_lsn(self):
        if self.is_witness: return "0/0"
        
        query = """
        SELECT CASE 
            WHEN pg_is_in_recovery() THEN GREATEST(COALESCE(pg_last_wal_receive_lsn(), '0/0'), COALESCE(pg_last_wal_replay_lsn(), '0/0'))
            ELSE pg_current_wal_lsn() 
        END;
        """
        res = self.safe_db_query(query)
        return res if res else "0/0"

    def lsn_to_int(self, lsn_string):
        """Конвертирует LSN строку (0/4028E10) в целое число для математического сравнения"""
        if not lsn_string or "/" not in lsn_string:
            return 0
        try:
            parts = lsn_string.split('/')
            high_bits = int(parts[0], 16)
            low_bits = int(parts[1], 16)
            return (high_bits << 32) + low_bits
        except Exception:
            return 0

    def promote_node(self):
        if self.is_witness: return
        self.log("!!! EMERGENCY ACTION: PROMOTING TO MASTER !!!")
        self.send_event(f"PROMOTION INITIATED for {self.cluster_id}")
        
        # Используем параметры из конфига
        cmd = ["sudo", "-u", "postgres", self.pg_ctl_bin, self.pg_version, self.pg_instance_name, "promote"]
        subprocess.run(cmd, stderr=subprocess.DEVNULL)
        self.role = "LEADER"

    def demote_node(self, reason_text):
        if self.is_witness: return
        self.log(f"!!! FENCING !!! Reason: {reason_text}")
        # Останавливаем конкретную службу
        subprocess.run(["systemctl", "stop", self.pg_service], stderr=subprocess.DEVNULL)
        self.role = "STANDBY"
        self.leader_name = None

    # --------------------------------------------------------------------------
    # МЕТОДЫ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ (LAYER 1 MESH)
    # --------------------------------------------------------------------------

    def gorgona_send(self, message_text, ttl_sec_override=None):
        """Отправка зашифрованного сообщения через бинарный клиент gorgona"""
        # Используем TTL из вызова или значение по умолчанию из конфига
        actual_ttl = ttl_sec_override if ttl_sec_override is not None else self.default_ttl
        
        now_utc = datetime.now(timezone.utc)
        start_str = now_utc.strftime('%Y-%m-%d %H:%M:%S')
        expire_time = now_utc + timedelta(seconds=actual_ttl)
        end_str = expire_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Формируем список аргументов для безопасного выполнения (без оболочки shell)
        cmd = [self.gorgona_bin, "send", start_str, end_str, message_text, self.pub_key_arg]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.log("Gorgona network error: " + str(e))

    def send_event(self, event_description):
        """Отправляет важное событие в Аудит-лог меша ( Audit Log )"""
        msg = "EVENT|" + str(self.node_name) + "|" + str(event_description)
        # События живут долго (event_ttl), чтобы админ мог прочитать их спустя часы
        self.gorgona_send(msg, ttl_sec_override=self.event_ttl)
        self.log("AUDIT: " + str(event_description))

    def broadcast_status(self):
        if self.role != "LEADER": return
        current_lsn_val = self.get_pg_lsn()
        msg = f"LEADER_STATUS|{self.cluster_id}|{self.node_name}|{current_lsn_val}"
        self.gorgona_send(msg, ttl_sec_override=self.heartbeat_ttl)

    def warmup_mesh_state(self):
        """Проверка истории меша перед запуском HA цикла (избежание ложных выборов)"""
        self.log("Warmup: Checking mesh for an active leader status...")
        # Читаем 5 последних сообщений из канала управления
        cmd = [self.gorgona_bin, "listen", "last", "5", self.my_pub_hash]
        try:
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
            lines = res.splitlines()
            for line in lines:
                if "|" in line:
                    # Обрабатываем исторические сообщения как входящие
                    self.process_message(line.strip())
        except Exception as e:
            self.log("Warmup notice: history not available (" + str(e) + ")")

    def auto_rebuild(self, target_master_host, reason_description):
        """Процедура автоматического запуска ребилда базы (Patroni-style self-healing)"""
        # Блокировка от повторных запусков
        with self.lock:
            if self.is_witness == True:
                return
            if self.rebuild_in_progress == True:
                return
            self.rebuild_in_progress = True
        
        self.log("!!! AUTO-REBUILD TRIGGERED !!! Target Master: " + str(target_master_host))
        self.send_event("Starting REBUILD cycle from Master: " + str(target_master_host) + ". Reason: " + reason_description)
        
        def run_recovery_task():
            try:
                # ПРОВЕРКА: существует ли скрипт на диске
                if os.path.exists(self.rebuild_script):
                    # Запускаем bash-скрипт восстановления. $1 = имя мастера
                    subprocess.run(
                        ["/bin/bash", self.rebuild_script, self.config_full_path, str(target_master_host)],
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
            except Exception as e:
                self.log("Background recovery thread error: " + str(e))
                self.send_event("RECOVERY FAILED: " + str(e))
            finally:
                self.log("Recovery process finished. RESYNCING node status.")
                # Снимаем флаг активности
                with self.lock:
                    self.rebuild_in_progress = False
                # Пауза для того, чтобы Postgres успел стартовать и открыть порты
                time.sleep(10)
                # Синхронизируем роль с реальностью
                self.sync_role_with_db()
                if self.role == "STANDBY":
                    self.send_event("RECOVERY COMPLETED. Node is back in cluster.")

        # Запускаем поток в режиме демона
        recovery_thread = threading.Thread(target=run_recovery_task, daemon=True)
        recovery_thread.start()
        
        self.role = "STANDBY"
        self.leader_name = target_master_host

    # --------------------------------------------------------------------------
    # ОБРАБОТКА СЕТЕВЫХ СОБЫТИЙ (LISTENER & BRAIN)
    # --------------------------------------------------------------------------

    def listener_thread(self):
        """Основной поток: Слушает зашифрованный меш и ловит статусы соседей"""
        self.log("Mesh Listener Thread active on hash " + str(self.my_pub_hash))
        
        # 'stdbuf -oL' гарантирует, что мы получаем строки сразу, без буферизации
        # Мы НЕ используем флаг '-e', чтобы Python сам управлял логикой
        cmd = ["stdbuf", "-oL", self.gorgona_bin, "listen", "new", self.my_pub_hash]
        
        try:
            # Открываем процесс и перехватываем stdout
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            # Флаг многострочного парсинга (для сообщений после 'Decrypted Content:')
            is_content_on_next_line = False
            
            for line in proc.stdout:
                if self.is_running == False: 
                    break
                
                raw_line = line.strip()
                if not raw_line: 
                    continue
                
                # СЛУЧАЙ А: Данные и маркер протокола в одной строке (LEADER_STATUS|... или CANDIDATE|...)
                if "|" in raw_line and ("LEADER_STATUS|" in raw_line or "CANDIDATE|" in raw_line):
                    self.process_message(raw_line)
                    is_content_on_next_line = False
                
                # СЛУЧАЙ Б: Нашли заголовок расшифрованного текста
                elif "Decrypted Content:" in raw_line:
                    is_content_on_next_line = True
                    continue
                
                # СЛУЧАЙ В: Предыдущая строка была заголовком, значит эта - суть сообщения
                elif is_content_on_next_line == True:
                    if "|" in raw_line:
                        self.process_message(raw_line)
                    is_content_on_next_line = False
                    
        except Exception as e:
            self.log("CRITICAL ERROR: Mesh Listener Thread crashed: " + str(e))

    def process_message(self, raw_payload):
        """Бизнес-логика разрешения конфликтов и обработки сигналов меша"""
        pattern = r"(LEADER_STATUS|CANDIDATE)\|([^|]+)\|([^|]+)\|([0-9a-fA-F/]+)" 
        match = re.search(pattern, raw_payload)
        
        if not match: 
            return

        # Извлекаем данные из групп RegEx
        msg_type, msg_cid, s_name, s_lsn = match.groups() 
        
        # Игнорируем свои собственные пакеты
        if s_name == self.node_name: return
        # дополнительная проверка, даже если ключи разные
        if msg_cid != self.cluster_id: return

        with self.lock:
            # --- СЦЕНАРИЙ 1: Получен статус действующего Лидера ---
            if msg_type == "LEADER_STATUS":
                self.last_leader_heartbeat = time.time()
                self.leader_name = s_name
                
                # Если мы сами пытались стать лидером, но услышали Мастера - отступаем
                if self.role == "CANDIDATE":
                    self.log("Leader pulse heard from " + s_name + ". Election aborted.")
                    self.role = "STANDBY"
                
                if self.role == "LEADER":
                    # КОНФЛИКТ МАСТЕРОВ (Split-Brain)
                    # Свежий LSN перед сравнением (не кэш)
                    my_lsn_val = self.lsn_to_int(self.get_pg_lsn())
                    rem_lsn_val = self.lsn_to_int(s_lsn)

                    # Победитель: больший LSN, при равенстве — меньшее имя
                    i_am_inferior = (
                        rem_lsn_val > my_lsn_val or
                        (rem_lsn_val == my_lsn_val and s_name < self.node_name)
                    )

                    if i_am_inferior:
                        self.demote_node("Superior leader found: " + s_name + " (LSN " + s_lsn + ")")
                        self.auto_rebuild(s_name, "Rejoining as replica (split-brain resolution)")
                    else:
                        self.log("Conflict with " + s_name + ". I have priority (LSN/name). Staying Master.")
                
                elif self.role == "STANDBY":
                    my_lsn_val = self.lsn_to_int(self.current_lsn)
                    # САМОЛЕЧЕНИЕ: Мы реплика с пустой базой или сломанным линком
                    if not self.rebuild_in_progress and not self.is_witness:
                        if my_lsn_val == 0:
                            self.log("DB is empty. Starting auto-initialization from " + s_name)
                            self.auto_rebuild(s_name, "Empty database trigger")
                        elif self.is_replication_active() == False:
                            if (time.time() - self.last_leader_heartbeat) < 30:
                                self.auto_rebuild(s_name, "Broken replication link recovery")

            # --- СЦЕНАРИЙ 2: Кто-то другой хочет стать Лидером ---
            elif msg_type == "CANDIDATE":
                if self.role in ["LEADER", "CANDIDATE"]:
                    # Свежий LSN перед сравнением
                    my_lsn_val = self.lsn_to_int(self.get_pg_lsn())
                    rem_lsn_val = self.lsn_to_int(s_lsn)
                    
                    # Если чужой кандидат "сильнее" нас
                    if rem_lsn_val > my_lsn_val or (rem_lsn_val == my_lsn_val and s_name < self.node_name):
                        if self.role == "LEADER":
                            # Если мы лидер, но кандидат лучше — ФИЗИЧЕСКИЙ СТОП
                            self.demote_node("Yielding to superior CANDIDATE: " + s_name)
                            self.auto_rebuild(s_name, "Rejoining after superior candidate election")
                        else:
                            self.log("Yielding candidacy to superior node: " + s_name)
                            self.role = "STANDBY"
                        
                        self.last_leader_heartbeat = time.time()

    # --------------------------------------------------------------------------
    # ГЛАВНЫЙ ЦИКЛ УПРАВЛЕНИЯ (HEARTBEAT & ELECTION)
    # --------------------------------------------------------------------------

    def manager_loop(self):
        """Бесконечный цикл HA-проверок (шаг 5 секунд)"""
        last_hb_sent_at = 0 
        
        while self.is_running:
            now = time.time()
            self.current_lsn = self.get_pg_lsn()
            # 1. Синхронизируем роль с реальностью Postgres
            if not self.is_witness and not self.rebuild_in_progress:
                try: self.sync_role_with_db()
                except Exception: pass
            
            # 2. ОБНОВЛЯЕМ LSN (самая свежая информация для всех потоков) 
            my_lsn_val = self.lsn_to_int(self.current_lsn)
            silence_time = now - self.last_leader_heartbeat

            # --- ЛОГИКА ЛИДЕРА ---
            if self.role == "LEADER":
                # Мастер зануляет имя лидера в своем статусе
                self.leader_name = None
                if (now - last_hb_sent_at) > self.heartbeat_interval:
                    self.broadcast_status()
                    last_hb_sent_at = now
            
            # --- ЛОГИКА РЕПЛИКИ (STANDBY) ---
            elif self.role == "STANDBY":
                last_hb_sent_at = 0 
                
                # ПРИОРИТЕТ 1: Выборы (если лидера нет слишком долго)
                if silence_time > self.election_timeout:
                    if not self.is_witness and not self.rebuild_in_progress:
                        # Узел с пустой базой не имеет права голосовать (нет данных - нет кворума)
                        if my_lsn_val > 0:
                            self.log("TIMEOUT: No pulse from leader for " + str(int(silence_time)) + "s. Initiating election.")
                            # Сбрасываем флаг ребилда: если лидер умер, ребилд не поможет
                            self.rebuild_in_progress = False 
                            self.start_election()
                        else:
                            if int(now) % 60 == 0:
                                self.log("Standby mode: Database is empty. Waiting for a master...")

                # ПРИОРИТЕТ 2: Ребилд (если лидер слышен, но репликация сломана)
                elif not self.is_witness and not self.rebuild_in_progress and self.leader_name:
                    if my_lsn_val == 0 or self.is_replication_active() == False:
                        # Чинимся только если мастер вещал в последние 30 сек (он жив)
                        if silence_time < 30:
                            self.log("LOOP TRIGGER: Replication check failed. Automatic recovery from " + str(self.leader_name))
                            self.auto_rebuild(self.leader_name, "Periodic health check failed")

            # 4. Обновление локального JSON статуса (для Stheno UI)
            try:
                status_obj = {
                    "node": str(self.node_name), 
                    "role": str(self.role), 
                    "lsn": str(self.current_lsn), 
                    "leader": str(self.leader_name), 
                    "rebuild_active": self.rebuild_in_progress, 
                    "update_time": time.time()
                }
                with open(self.status_json_path, "w") as f: 
                    json.dump(status_obj, f, indent=4)
            except Exception: pass
            
            # 5. MONITOR телеметрия
            if (now - self.last_monitor_sent) > self.monitor_interval:
                repl_status = self.get_replication_status()
                monitor_msg = ("MONITOR|" + str(self.node_name) + "|" + str(self.role) +
                               "|" + str(self.current_lsn) + "|" + repl_status)
                self.gorgona_send(monitor_msg)
                self.last_monitor_sent = now
            
            # Шаг итерации - 5 секунд
            time.sleep(5)

    def start_election(self):
        """Протокол проведения выборов кандидата"""
        if self.is_witness == True: return
        
        self.role = "CANDIDATE"
        lsn_at_election = self.get_pg_lsn()
        self.log("ELECTION: Broadcasting candidacy. Local LSN: " + str(lsn_at_election))
        self.send_event("INITIATING ELECTION. Local LSN: " + str(lsn_at_election))
        
        # Заявка живет 20 секунд
        self.gorgona_send("CANDIDATE|" + str(self.node_name) + "|" + str(lsn_at_election), ttl_sec_override=20)
        
        # Окно ожидания для оспорений (10 секунд)
        time.sleep(10)
        
        # Если за 10 секунд нас не перевели обратно в STANDBY через process_message (никто не прислал LSN лучше)
        if self.role == "CANDIDATE":
            self.log("ELECTION WON: No superior nodes found. Seizing leadership.")
            self.promote_node()

# ==============================================================================
# [ ТОЧКА ВХОДА (MAIN) ]
# ==============================================================================

if __name__ == "__main__":
    # Сначала создаем экземпляр, чтобы загрузились пути из gfm.conf
    gfm_daemon = GFM()
    
    # Теперь проверяем наличие ключа безопасности
    if not os.path.exists(gfm_daemon.priv_key_path):
        print("FATAL ERROR: Control key " + gfm_daemon.priv_key_path + " not found!")
        print("Please check your MY_PUB_HASH in gfm.conf")
        sys.exit(1)

    # Запуск фонового сетевого слушателя в отдельном потоке
    listener = threading.Thread(target=gfm_daemon.listener_thread, daemon=True)
    listener.start()
    
    # Запуск основного бесконечного цикла в главном потоке
    try:
        gfm_daemon.manager_loop()
    except KeyboardInterrupt:
        gfm_daemon.is_running = False
        print("\nGFM shutdown initiated by user.")
        sys.exit(0)
    except Exception as fatal_e:
        print("\nGFM CRASHED: " + str(fatal_e))
        sys.exit(1)
