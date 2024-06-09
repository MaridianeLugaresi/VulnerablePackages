import pyshark
import re

FILE_PATH = 'packageCapture.pcapng'

def process_pcap():

    capture = pyshark.FileCapture(FILE_PATH)

    for packet in capture:
        try:
            # Protocols considered vulnerable
            if 'HTTP' in packet:
                http_protocol(packet)

        except AttributeError as e:
            print(f'Error processing package: {e}')

def http_protocol(packet):

    keywords_vulnerable = ['usuario', 'user', 'senha', 'password']

    print('Detected HTTP protocol')

    # View HTTP information
    http_layer = packet.http

    print(f'ID package: {packet.number}')
    print(f'Source IP address: {packet.ip.src}')
    print(f'Destination IP address: {packet.ip.dst}')

    print(f'HTTP method: {http_layer.get_field_value("request_method")}')
    print(f'Host: {http_layer.get_field_value("host")}')
    print(f'URL: {http_layer.get_field_value("request_full_uri")}')

    # View HTML content
    if hasattr(http_layer, 'file_data') and http_layer.file_data:
        try:
            html_content = bytes.fromhex(http_layer.file_data.replace(':', '')).decode('utf-8', errors='replace')
            print(f'Conteúdo HTML:\n{html_content}')

            for keyword in keywords_vulnerable:
                if re.search(keyword, html_content, re.IGNORECASE):
                    print(f'Found keyword: {keyword}')

        except ValueError as ve:
            print("The package haven't layer HTML")

    print('------------------------------------')

if __name__ == '__main__':
    process_pcap()
