import pyshark
import re
import dash
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from dash import dcc, html
from dash.dependencies import Input, Output

FILE_PATHS = ['../packageCapture.pcapng','../FTPCapture.pcap']

vulnerabilities = {
    'http': 0,
    'ftp': 0
}

http_packets = []
ftp_packets = []

def process_pcap():

    for file_path in FILE_PATHS:

        capture = pyshark.FileCapture(file_path)

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
            print(f'HTML content:\n{html_content}')

            # Search if content have keywords vulnerable
            for keyword in keywords_vulnerable:
                if re.search(keyword, html_content, re.IGNORECASE):
                    print(f'Found keyword: {keyword}')
                    vulnerabilities['http'] += 1
                    http_packets.append({
                        'id': packet.number,
                        'src_ip': packet.ip.src,
                        'dst_ip': packet.ip.dst,
                        'method': http_layer.get_field_value("request_method"),
                        'host': http_layer.get_field_value("host"),
                        'uri': http_layer.get_field_value("request_full_uri"),
                        'content': html_content
                    })

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
            vulnerabilities['ftp'] += 1
            ftp_packets.append({
                'id': packet.number,
                'command': ftp_layer.request_command,
                'arg': ftp_layer.request_arg
            })

    if hasattr(ftp_layer, 'response_code'):
        print(f'FTP response code: {ftp_layer.response_code}')

    if hasattr(ftp_layer, 'response_arg'):
        print(f'FTP response arg: {ftp_layer.response_arg}')

    print('------------------------------------')

def create_dashboard(vulnerabilities):
    app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
    protocols = list(vulnerabilities.keys())
    counts = list(vulnerabilities.values())
    
    bar_chart = dcc.Graph(
        id='vulnerability-bar-chart',
        figure={
            'data': [
                go.Bar(x=protocols, y=counts, marker_color=['violet', 'green'])
            ],
            'layout': go.Layout(
                title='Vulnerabilities Found by Protocol',
                xaxis={'title': 'Protocols'},
                yaxis={'title': 'Number of Vulnerabilities'}
            )
        }
    )

    app.layout = dbc.Container([
        dbc.Row(dbc.Col(html.H2("Network Vulnerability Dashboard"))),
        dbc.Row(dbc.Col(bar_chart)),
        dbc.Row(dbc.Col(html.H4("Details of Vulnerable Packets"))),
        dbc.Row(dbc.Col(html.Div(id='details'))),
    ], fluid=True)

    @app.callback(
        Output('details', 'children'),
        [Input('vulnerability-bar-chart', 'clickData')]
    )

    def update_details(clickData):
        details = []
        if clickData:
            protocol = clickData['points'][0]['x']
            if protocol == 'http':
                details.append(html.H5("Vulnerable HTTP Packets"))
                details.append(html.Ul([html.Li(f"ID {packet['id']}: {packet['method']} {packet['uri']} {packet['content']}") for packet in http_packets]))
            if protocol == 'ftp':
                details.append(html.H5("Vulnerable FTP Packets"))
                details.append(html.Ul([html.Li(f"ID {packet['id']}: {packet['command']} {packet['arg']}") for packet in ftp_packets]))

        return details
    
    return app

if __name__ == '__main__':
    process_pcap()
    app = create_dashboard(vulnerabilities)
    app.run_server()