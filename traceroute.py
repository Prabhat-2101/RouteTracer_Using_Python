import time
import re
from flask import Flask, request, render_template
import subprocess
import pyshark
import networkx as nx
import plotly.graph_objects as go
import asyncio
import socket
hostname = socket.gethostname()
hostIPAddr = socket.gethostbyname(hostname)

app = Flask(__name__)


def perform_traceroute(target):
    result = subprocess.run(['tracert', target], capture_output=True, text=True, shell=True)
    output = result.stdout
    pattern = re.compile(r'(\d+)\s+((?:\d+ ms\s+){3})((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|Request timed out))')
    lines = output.splitlines()
    hops = []
    for line in lines:
        match = pattern.match(line.strip())
        if match:
            hop_number = match.group(1)
            timings = [value for value in match.group(2).strip().split() if value.isdigit()]
            dest_hop_ip = match.group(3)
            hops.append({
                "destIp": dest_hop_ip
            })
            source_hop_ip = dest_hop_ip
    return hops


def capture_packets(interface, timeout=30, max_packets=50):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    capture = pyshark.LiveCapture(interface=interface)
    start_time = time.time()
    packets = []

    for packet in capture.sniff_continuously():
        packets.append(packet)
        if len(packets) >= max_packets or (time.time() - start_time) > timeout:
            break

    return packets


def analyze_packets(capture, hops):
    analysis = {hop['destIp']: [] for hop in hops}
    for packet in capture:
        if 'IP' in packet and packet.ip.src in hops and packet.ip.dst in hops:
            layer_data = {
                'source': packet.ip.src,
                'destination': packet.ip.dst,
                'layers': []
            }
            for layer in packet.layers:
                layer_info = {
                    'layer_name': layer.layer_name,
                    'fields': {field: layer.get_field_value(field) for field in layer.field_names}
                }
                layer_data['layers'].append(layer_info)
            analysis[packet.ip.src].append(layer_data)
    return analysis


def visualize_packet_interactions(analysis):
    G = nx.DiGraph()
    for hop, packets in analysis.items():
        G.add_node(hop)
        for packet in packets:
            src = packet['source']
            dst = packet['destination']
            G.add_edge(src, dst)

    pos = nx.spring_layout(G)
    edge_x = []
    edge_y = []

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_x.append(None)
        edge_y.append(y0)
        edge_y.append(y1)
        edge_y.append(None)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            size=10,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line_width=2))

    node_text = []
    for node in G.nodes():
        node_text.append(f'IP: {node}')

    node_trace.text = node_text

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title='Packet Interactions',
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20, l=5, r=5, t=40)))
    return fig.to_html()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/trace', methods=['POST'])
def trace():
    target = "www.google.com"
    interface = "Wi-Fi"  # Set the interface to Wi-Fi

    print(f"Pinging {target}... from Host: {hostIPAddr}")
    print(f"Performing traceroute to {target}...")
    hops = perform_traceroute(target)
    print(f"Hops: {hops}")

    print("Capturing packets...")
    capture = capture_packets(interface, timeout=60)

    print("Analyzing packets...")
    analysis = analyze_packets(capture, hops)

    print("Visualizing packet interactions...")
    graph_html = visualize_packet_interactions(analysis)

    return render_template('graph.html', graph_html=graph_html)

if __name__ == "__main__":
    app.run(debug=True)
