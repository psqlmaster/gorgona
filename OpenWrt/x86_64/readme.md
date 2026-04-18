# Руководство по сборке Gorgona для OpenWrt (x86_64)

### 1. Подготовка хост-системы (Debian 13)
Установите необходимые инструменты сборки и системные зависимости:
```bash
sudo apt update
sudo apt install build-essential libncurses-dev zlib1g-dev gawk \
git gettext libssl-dev xsltproc rsync wget unzip python3
```

---

### 2. Загрузка и распаковка SDK
Скачайте SDK, соответствующий версии прошивки вашего роутера (**23.05.4 x86_64**):

```bash
mkdir -p ~/crosscompile && cd ~/crosscompile
wget https://downloads.openwrt.org/releases/23.05.4/targets/x86/64/openwrt-sdk-23.05.4-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz
wget https://downloads.openwrt.org/releases/24.10.6/targets/x86/64/openwrt-sdk-24.10.6-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst 
tar -xf openwrt-sdk-23.05.4-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz
tar -xvf openwrt-sdk-24.10.6-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst  

cd ~/crosscompile/openwrt-sdk-25.12.2...
# Удаляем индекс пакетов и временные файлы конфигурации
rm -rf tmp && rm -f .config .config.old
# 1. Обновляем индекс пакетов
./scripts/feeds update base
./scripts/feeds install zlib libopenssl

# проверим, где именно SDK «видит» эти пакеты. Это критично для команды make:
find package -name Makefile | grep -E "zlib|openssl"
# Если пусто — выполни принудительное копирование (метод «грубой силы»):
# Копируем исходники из фидов в основную директорию сборки
mkdir -p package/libs && \
cp -r feeds/base/package/libs/zlib package/libs/ && \
cp -r feeds/base/package/libs/openssl package/libs/

# 3. Конфигурация SDK
# Выберите в Libraries -> libopenssl через [*] (Build-in), сохраните и выйдите
make menuconfig 

# Или принудительно через командную строку:
echo "CONFIG_PACKAGE_libopenssl=y" >> .config
echo "CONFIG_PACKAGE_zlib=y" >> .config

# Обновляем зависимости
make defconfig

# 4. Компиляция OpenSSL (занимает ~1500 минут)
sudo make package/compile -j$(nproc) V=s
```
---

### 5. Финальная сборка
Запустите компиляцию проекта:
```bash
cd ~/repository/c/gorgona/OpenWrt_x86_64
make clean
make
```

Проверьте, что файлы являются 64-битными:
```bash
file gorgonad_owrt
# Ожидаемый вывод: ELF 64-bit LSB executable, x86-64, interpreter /lib/ld-musl-x86_64.so.1
```

---

### 6. Деплой и запуск на OpenWrt
Поскольку SSH-сервер (Dropbear) в OpenWrt часто не имеет поддержки SFTP, используйте классический протокол SCP (флаг `-O`):

```bash
# Копируем на роутер
scp -O gorgonad_owrt root@192.168.1.1:/usr/bin/gorgonad
scp -O gorgona_owrt root@192.168.1.1:/usr/bin/gorgona

# Заходим на роутер
ssh root@192.168.1.1

# Выдаем права и проверяем зависимости
chmod +x /usr/bin/gorgonad /usr/bin/gorgona
opkg update
opkg install libopenssl  # Если библиотеки отсутствуют в прошивке

# Запуск
gorgonad --help
```

---

### Решение типичных проблем
1.  **"No rule to make target 'package/.../compile'"**: Убедитесь, что вы удалили папку `tmp` в корне SDK и выполнили `make defconfig` после копирования исходников OpenSSL в `package/libs`.
2.  **Ошибка :192 в портах (Layer 2)**: Убедитесь, что вы используете последнюю версию парсера `process_mgmt_frame` из наших обсуждений, который корректно разделяет IP и Port.
3.  **История начинается с 1970 года**: BMC/OpenWrt часто не имеют RTC. Проверьте синхронизацию времени по NTP перед запуском (`ntpd -n -q -p pool.ntp.org`).
