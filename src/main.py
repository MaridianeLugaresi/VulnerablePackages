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

            if 'FTP' in packet:
                ftp_protocol(packet)

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

            # Search if content have keywords vulnerable
            for keyword in keywords_vulnerable:
                if re.search(keyword, html_content, re.IGNORECASE):
                    print(f'Found keyword: {keyword}')

        except ValueError as ve:
            print("The package haven't layer HTML")

    print('------------------------------------')

def ftp_protocol(packet):

    # Regular expression to find email pattern
    email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
                               
    print('Detected FTP protocol')

    ftp_layer = packet.ftp
    print(f'ID package: {packet.number}')
    
    if hasattr(ftp_layer, 'request_command'):
        print(f'FTP command: {ftp_layer.request_command}')

    if hasattr(ftp_layer, 'request_arg'):
        print(f'FTP argument: {ftp_layer.request_arg}')

        # Search if arguments have email
        if email_pattern.search(ftp_layer.request_arg):
            print(f'Found email address: {ftp_layer.request_arg}')

    if hasattr(ftp_layer, 'response_code'):
        print(f'FTP response code: {ftp_layer.response_code}')

    if hasattr(ftp_layer, 'response_arg'):
        print(f'FTP response arg: {ftp_layer.response_arg}')

    print('------------------------------------')

if __name__ == '__main__':
    process_pcap()
