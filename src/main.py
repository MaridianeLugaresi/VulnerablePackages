import pyshark

FILE_PATH = '../packageCapture.pcapng'

def process_pcap():

    capture = pyshark.FileCapture(FILE_PATH)

    for packet in capture:
        try:
            print(f'Número do pacote: {packet.number}')
            print(f'Timestamp: {packet.sniff_time}')
            print(f'Camadas: {packet.layers}')

            if 'IP' in packet:
                print(f'Endereço IP de origem: {packet.ip.src}')
                print(f'Endereço IP de destino: {packet.ip.dst}')
            
            if 'TCP' in packet:
                print(f'Porta de origem: {packet.tcp.srcport}')
                print(f'Porta de destino: {packet.tcp.dstport}')
            elif 'UDP' in packet:
                print(f'Porta de origem: {packet.udp.srcport}')
                print(f'Porta de destino: {packet.udp.dstport}')
            
            print('------------------------------------')

        except AttributeError as e:
            print(f'Erro ao processar pacote: {e}')

if __name__ == '__main__':
    process_pcap()
