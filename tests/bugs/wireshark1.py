import pyshark
import collections
import sys
from datetime import datetime

def analyze_fasthttp_connections(pcap_file):
    print(f"Analyzing FastHTTP connections in {pcap_file}...")
    
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)
    
    # Data structures to track connections
    connections = {}  # key: (src_ip, src_port, dst_ip, dst_port), value: connection data
    connection_ends = {}  # Track how connections ended (FIN or RST)
    http_responses = {}  # Track HTTP responses for each connection
    
    # Counters
    rst_count = 0
    fin_count = 0
    total_connections = 0
    http_requests = 0
    http_responses_count = 0
    connection_close_headers = 0
    
    # Process each packet
    for i, packet in enumerate(cap):
        # Status update every 10000 packets
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i} packets...")
        
        try:
            if 'TCP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                
                # Create bidirectional connection key
                conn_key_forward = (src_ip, src_port, dst_ip, dst_port)
                conn_key_reverse = (dst_ip, dst_port, src_ip, src_port)
                
                # Track connection establishment
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    connections[conn_key_forward] = {
                        'start_time': float(packet.sniff_timestamp),
                        'syn_sent': True,
                        'established': False,
                        'packets': 1,
                        'bytes': int(packet.length)
                    }
                    total_connections += 1
                
                # Track connection establishment acknowledgment
                elif hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                    if conn_key_reverse in connections:
                        connections[conn_key_reverse]['syn_ack_received'] = True
                        connections[conn_key_reverse]['packets'] = connections[conn_key_reverse].get('packets', 0) + 1
                        connections[conn_key_reverse]['bytes'] = connections[conn_key_reverse].get('bytes', 0) + int(packet.length)
                
                # Track established connections
                elif packet.tcp.flags_ack == '1' and not hasattr(packet.tcp, 'flags_syn'):
                    for key in [conn_key_forward, conn_key_reverse]:
                        if key in connections and not connections[key].get('established', False):
                            connections[key]['established'] = True
                            connections[key]['packets'] = connections[key].get('packets', 0) + 1
                            connections[key]['bytes'] = connections[key].get('bytes', 0) + int(packet.length)
                
                # Track connection reset
                if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1':
                    rst_count += 1
                    for key in [conn_key_forward, conn_key_reverse]:
                        if key in connections:
                            connection_ends[key] = 'RST'
                            connections[key]['end_time'] = float(packet.sniff_timestamp)
                            connections[key]['duration'] = connections[key]['end_time'] - connections[key]['start_time']
                
                # Track connection normal termination
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                    fin_count += 1
                    for key in [conn_key_forward, conn_key_reverse]:
                        if key in connections and key not in connection_ends:
                            connection_ends[key] = 'FIN'
                            connections[key]['end_time'] = float(packet.sniff_timestamp)
                            connections[key]['duration'] = connections[key]['end_time'] - connections[key]['start_time']
                
                # Track HTTP requests and responses
                if 'HTTP' in packet:
                    if hasattr(packet.http, 'request'):
                        http_requests += 1
                        for key in [conn_key_forward, conn_key_reverse]:
                            if key in connections:
                                connections[key]['has_http_request'] = True
                                if hasattr(packet.http, 'request_method'):
                                    connections[key]['http_method'] = packet.http.request_method
                                if hasattr(packet.http, 'request_uri'):
                                    connections[key]['http_uri'] = packet.http.request_uri
                    
                    if hasattr(packet.http, 'response'):
                        http_responses_count += 1
                        for key in [conn_key_forward, conn_key_reverse]:
                            if key in connections:
                                connections[key]['has_http_response'] = True
                                if hasattr(packet.http, 'response_code'):
                                    connections[key]['http_status'] = packet.http.response_code
                                    http_responses[key] = packet.http.response_code
                                
                                # Check for Connection: close header
                                if hasattr(packet.http, 'connection') and 'close' in packet.http.connection.lower():
                                    connections[key]['has_connection_close'] = True
                                    connection_close_headers += 1
        
        except Exception as e:
            print(f"Error processing packet {i}: {e}")
    
    # Analyze results
    print("\n===== FASTHTTP CONNECTION ANALYSIS =====")
    print(f"Total TCP connections: {total_connections}")
    print(f"Connections ended with FIN: {fin_count}")
    print(f"Connections ended with RST: {rst_count}")
    print(f"HTTP requests: {http_requests}")
    print(f"HTTP responses: {http_responses_count}")
    print(f"Responses with 'Connection: close' header: {connection_close_headers}")
    
    # Analyze connections that ended with RST
    rst_connections = [conn for key, conn in connections.items() if connection_ends.get(key) == 'RST']
    if rst_connections:
        print("\n===== RST CONNECTION ANALYSIS =====")
        print(f"Number of connections terminated with RST: {len(rst_connections)}")
        
        # Check if RST connections had HTTP responses
        rst_with_response = sum(1 for conn in rst_connections if conn.get('has_http_response', False))
        print(f"RST connections with HTTP responses: {rst_with_response}")
        print(f"RST connections without HTTP responses: {len(rst_connections) - rst_with_response}")
        
        # Check Connection: close header presence in RST connections
        rst_with_close_header = sum(1 for conn in rst_connections if conn.get('has_connection_close', False))
        print(f"RST connections with 'Connection: close' header: {rst_with_close_header}")
        print(f"RST connections without 'Connection: close' header: {len(rst_connections) - rst_with_close_header}")
        
        # Analyze duration of RST connections
        if rst_connections:
            avg_duration = sum(conn.get('duration', 0) for conn in rst_connections) / len(rst_connections)
            print(f"Average duration of RST connections: {avg_duration:.6f} seconds")
    
    # Find connections where RST occurred without Connection: close header
    problematic_connections = [
        conn for key, conn in connections.items() 
        if connection_ends.get(key) == 'RST' 
        and conn.get('has_http_response', False) 
        and not conn.get('has_connection_close', False)
    ]
    
    if problematic_connections:
        print("\n===== POTENTIAL FASTHTTP CONNECTION ISSUES =====")
        print(f"Found {len(problematic_connections)} connections where the server sent an HTTP response but closed with RST without a 'Connection: close' header")
        print("This matches the FastHTTP error: 'the server closed connection before returning the first response byte'")
        
        # Sample some problematic connections
        sample_size = min(5, len(problematic_connections))
        print(f"\nSample of {sample_size} problematic connections:")
        for i, conn in enumerate(problematic_connections[:sample_size]):
            print(f"  Connection {i+1}:")
            print(f"    Duration: {conn.get('duration', 'N/A'):.6f} seconds")
            print(f"    HTTP Status: {conn.get('http_status', 'N/A')}")
            print(f"    HTTP Method: {conn.get('http_method', 'N/A')}")
            print(f"    HTTP URI: {conn.get('http_uri', 'N/A')}")
    
    print("\n===== FASTHTTP CONNECTION TIMING ANALYSIS =====")
    # Analyze connection durations
    all_durations = [conn.get('duration', 0) for conn in connections.values() if 'duration' in conn]
    if all_durations:
        avg_duration = sum(all_durations) / len(all_durations)
        print(f"Average connection duration: {avg_duration:.6f} seconds")
        
        # Compare RST vs FIN durations
        rst_durations = [conn.get('duration', 0) for key, conn in connections.items() 
                        if connection_ends.get(key) == 'RST' and 'duration' in conn]
        fin_durations = [conn.get('duration', 0) for key, conn in connections.items() 
                        if connection_ends.get(key) == 'FIN' and 'duration' in conn]
        
        if rst_durations:
            avg_rst_duration = sum(rst_durations) / len(rst_durations)
            print(f"Average RST connection duration: {avg_rst_duration:.6f} seconds")
        
        if fin_durations:
            avg_fin_duration = sum(fin_durations) / len(fin_durations)
            print(f"Average FIN connection duration: {avg_fin_duration:.6f} seconds")
    
    # Connection conclusions
    print("\n===== CONCLUSION =====")
    if rst_count > 0:
        rst_percentage = (rst_count / total_connections) * 100 if total_connections > 0 else 0
        print(f"RST connection percentage: {rst_percentage:.2f}%")
        
        if rst_percentage > 0.5:
            print("FINDING: There is a significant number of RST connections, which could explain the FastHTTP errors.")
            print("FastHTTP expects 'Connection: close' headers before connection termination.")
            
            if connection_close_headers / http_responses_count < 0.9 and http_responses_count > 0:
                print("PROBLEM: Many HTTP responses are missing the 'Connection: close' header before connection termination.")
                print("This matches the FastHTTP error: 'the server closed connection before returning the first response byte'")
        
        if problematic_connections:
            print("\nRECOMMENDATION: The issue appears to be with how connections are terminated between FastHTTP and the server.")
            print("The server is closing connections with RST after sending responses, but without properly signaling")
            print("via the 'Connection: close' header, which FastHTTP requires.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "wireshark_capture_1.pcapng"
    
    analyze_fasthttp_connections(pcap_file)