import time
from gorgona_sender import GorgonaSender

# Configuration
NODE_HOST = "64.188.70.158"
NODE_PORT = 7777
SYNC_PSK = "BQQCyN8zo4La2lRSIQ2jLp5imEa0JzdXp2PKogP3"
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC24qUDHCBeJXje
6qC+29XYCrFnYixMDwhtW25W/yAh211D8avwZcWkw8ecQzBhDK6KrJfVkzmGQf9I
0+VaGBrgTHPE+j3Aaq39t532GoCULK2bATR0/Y6Vc4k0eWsG+ERwyPGzjVi/noRx
AdVaxQLL7/W0I6qllvcBB1ezu21cOXd5XqyLlzsu69hyanWCIY7m5JdzDihawD7T
5Kj+9Xko1gsPDZQCelKhiSj9cZulEviS5wNUC+qnG1FON6avTx/JRS/j6yfW03m9
uSRHuLEoqjMA03gyNt4DKLFa4x1EuaFw5sbpusPY6TTnh6j6WLhb3dJ5KTH7N9gK
KrCO6kzRAgMBAAECggEAB26V7JatxQ2qSArKXf8yhT1IAM7HRI7+1WzYAs6K2H1g
4KQ3S8Vi/wNavwGm+2anyChj4jDBr3BKpsO/qAXfP7qzoK9Xp5RePjeCQpBIpdzb
8DbgEhoEu5OOoZSGkimwJFIyKk0F7IGNWcdMi4wChVWay0eAxYppPsA04u+srcjx
Y4bt82AOQzyOxA9MrA2+11u4GMwT9AewRclUm7r1HIVcrvGLpnDE9qfaxMYIRK+/
efLqJikTyiisceTs340pxs7FlNnY/543nOwfXKdunSI3ak9D43lvOjnXHpJ9Pe6y
fxsjZC1WBsNrPu3mf0RiiqQKHgniMxNWKIOW18pjzQKBgQDuqQhAjSRv3ZT/ZHSA
YRnFbwN8Xysw28EXDT/0LQkVTEZwLxgMOG1hLVPJgA8vL5wdhkYUD6yzIL2aflwx
ClgF/uyN30UPm514u4iXmgssonC36UaemDDd1ID1sYFPm5oEtx9IVj1DdZabkoV+
Q3y/jnbINcRgaEbWEPlsJ/ZvbQKBgQDELDmJ+qajr9h4P0opxUPHJr7dv+HWWOTu
xv5yiYlNZRUZtDmf6uJk1Tz/f51Liic52xyWcSroGrxWXq9KDgY7jnTzqbkeEvZx
v2KsqS4IWdT6t43KzLisnJ0UCAE90eKzdCYtDrLCGkY44xal7Za1okJqmF3Z0gr2
Z6mH8LLgdQKBgQDLZvaohWJrkM7/B2+fRqJ/OUkgQ7/8yR389obuJT/bjgFudUSq
jaDzNH13e5P1ZD9KjnjFekJ2/E18EXujNCynF4gmtgYW8kq4biRRCLHDXcJxi/hr
DEyBky5BuAH8hiIzKJsZvJ5EE0DD4JGzdfMpE1M6+VAf1l+g7CCXxEts1QKBgFdN
jzXWtL54DZBGKk04mxdQKPUq5eismwWgzbBPgSlOaPuNd2+x6psRQxo5wtjRXO+k
ka5qIrw02cheTwhYAXITzfx6dgXqTn8Eu3c3u2LAB8akVZgBT9aRxF4byeGnPIq8
kBjRR8CWTNYYSgYCHGYtFf22XV4I2hQawhnbht/ZAoGBAMLjZfEtYAY1V1ejMrFw
nwSm/ZONUpEtxr7xGyuF7cQ6LPoSYZS7usp/fjaW4x3dL7UJEC5kquzilaP4HcqC
+lnN02M2wyVqJTTEyFxGxlC+rrR9KsKmtqvvsYOaIQAFRXLTUr+gWAraYkDmxtjf
O5yRWtuXQMSD6Z8wggtGWy5c
-----END PRIVATE KEY-----"""

sender = GorgonaSender(NODE_HOST, NODE_PORT, SYNC_PSK)

# 1. Рассчитываем время (Unix Timestamp UTC)
now = int(time.time())
three_days_later = now + (3 * 24 * 3600)

# 2. Отправляем сообщение
# Теперь unlock_at = текущее время, expire_at = через 3 дня
result = sender.send_alert(
    private_key_pem=PRIVATE_KEY,
    message="System Alert: High CPU usage detected on Server-01",
    unlock_at=now,
    expire_at=three_days_later
)

print(f"Current UTC Time: {now}")
print(f"Server response: {result}")
