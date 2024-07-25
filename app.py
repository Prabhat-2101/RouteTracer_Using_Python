from flask import Flask, render_template, request
import json
import re
import subprocess
import socket
hostname = socket.gethostname()
hostIPAddr = socket.gethostbyname(hostname)

app = Flask(__name__)


@app.route('/trace', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['target']
        print(f'{request} is request')
        trace_data = trace_route(domain)

        with open('static/traceroute_data.json', 'w') as f:
            json.dump(trace_data, f)

        return render_template('index.html', data=trace_data)

    return render_template('index.html', data=None)


def trace_route(domain):
    result = subprocess.run(['tracert', domain], capture_output=True, text=True, shell=True)
    output = result.stdout
    pattern = re.compile(r'(\d+)\s+((?:\d+ ms\s+){3})((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|Request timed out))')
    lines = output.splitlines()
    hops, source_hop_ip = [], hostIPAddr
    for line in lines:
        match = pattern.match(line.strip())
        if match:
            hop_number = match.group(1)
            timings = [value for value in match.group(2).strip().split() if value.isdigit()]
            dest_hop_ip = match.group(3)

            hops.append({
                "hopNumber": hop_number,
                "packetDelay1": timings[0],
                "packetDelay2": timings[1],
                "packetDelay3": timings[2],
                "sourceIp": source_hop_ip,
                "destIp": dest_hop_ip
            })
            source_hop_ip = dest_hop_ip
    return hops


if __name__ == '__main__':
    app.run(debug=True)
