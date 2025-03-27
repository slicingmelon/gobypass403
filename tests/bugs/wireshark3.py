import pyshark
import collections
import sys
from datetime import datetime
import statistics

def analyze_fasthttp_tcp_behavior(pcap_file):
    print(f"Analyzing FastHTTP TCP behavior in {pcap_file}...")
    
    cap = pyshark.FileCapture(pcap_file)
    
    # Track TCP streams
    tcp_streams = {}
    http_requests_by_stream = {}
    http_responses_by_stream = {}
    rst_after_response = []
    premature_rst = []
    keepalive_connections = set()
    total_rst_packets = 0
    total_fin_packets = 0
    connection_close_headers = 0
    partial_handshakes = []
    complete_handshakes = []
    retransmissions = 0
    
    # Connection reuse tracking
    reused_connections = set()
    potential_reused_streams = {}
    tcp_ports_by_ip = {}
    
    # Silent termination detection
    idle_periods = []
    silently_terminated_streams = []
    
    acked_unseen_segments = 0
    rst_ack_packets = 0
    
    for i, packet in enumerate(cap):
  
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i} packets...")
        
        try:
            if 'TCP' in packet:
                # Track TCP stream ID for correlation
                stream_id = packet.tcp.stream
                
                # Record client and server information for port reuse detection
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                
                # Track ports used by each IP to detect connection reuse
                if src_ip not in tcp_ports_by_ip:
                    tcp_ports_by_ip[src_ip] = {}
                if dst_ip not in tcp_ports_by_ip:
                    tcp_ports_by_ip[dst_ip] = {}
                
                if src_port not in tcp_ports_by_ip[src_ip]:
                    tcp_ports_by_ip[src_ip][src_port] = set()
                if dst_port not in tcp_ports_by_ip[dst_ip]:
                    tcp_ports_by_ip[dst_ip][dst_port] = set()
                
                tcp_ports_by_ip[src_ip][src_port].add(stream_id)
                tcp_ports_by_ip[dst_ip][dst_port].add(stream_id)
                
                # If a port has multiple streams, it may indicate connection reuse
                if len(tcp_ports_by_ip[src_ip][src_port]) > 1 or len(tcp_ports_by_ip[dst_ip][dst_port]) > 1:
                    reused_connections.add(stream_id)
                
                # Track TCP handshake
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_syn'] = True
                    tcp_streams[stream_id]['syn_time'] = float(packet.sniff_timestamp)
                    
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '1':
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_syn_ack'] = True
                    
                if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1' and not hasattr(packet.tcp, 'flags_syn'):
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_ack'] = True
                
                # Count RST packets
                if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1':
                    total_rst_packets += 1
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_rst'] = True
                    tcp_streams[stream_id]['rst_time'] = float(packet.sniff_timestamp)
                    tcp_streams[stream_id]['rst_from'] = src_ip
                    
                    # Check if this stream had a response
                    if stream_id in http_responses_by_stream:
                        # This is a RST after a response was sent
                        rst_after_response.append({
                            'stream_id': stream_id,
                            'time': float(packet.sniff_timestamp),
                            'src': packet.ip.src,
                            'dst': packet.ip.dst
                        })
                
                # Count FIN packets
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin == '1':
                    total_fin_packets += 1
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_fin'] = True
                    tcp_streams[stream_id]['fin_time'] = float(packet.sniff_timestamp)
                    tcp_streams[stream_id]['fin_from'] = src_ip
                
                # Track TCP streams
                if stream_id not in tcp_streams:
                    tcp_streams[stream_id] = {
                        'packets': 0,
                        'first_packet_time': float(packet.sniff_timestamp),
                        'last_packet_time': float(packet.sniff_timestamp),
                        'client_ip': src_ip,
                        'server_ip': dst_ip,
                        'client_port': src_port,
                        'server_port': dst_port,
                        'packet_timestamps': [float(packet.sniff_timestamp)]
                    }
                else:
                    tcp_streams[stream_id]['last_packet_time'] = float(packet.sniff_timestamp)
                    if 'packet_timestamps' not in tcp_streams[stream_id]:
                        tcp_streams[stream_id]['packet_timestamps'] = []
                    tcp_streams[stream_id]['packet_timestamps'].append(float(packet.sniff_timestamp))
                
                tcp_streams[stream_id]['packets'] = tcp_streams[stream_id].get('packets', 0) + 1
                
                # Track HTTP information in this TCP stream
                if 'HTTP' in packet:
                    # HTTP Request
                    if hasattr(packet.http, 'request'):
                        if stream_id not in http_requests_by_stream:
                            http_requests_by_stream[stream_id] = []
                        
                        request_info = {
                            'time': float(packet.sniff_timestamp),
                            'method': getattr(packet.http, 'request_method', 'UNKNOWN'),
                            'uri': getattr(packet.http, 'request_uri', 'UNKNOWN')
                        }
                        
                        # Check for keep-alive header -- not present in the request but default in HTTP/1.1
                        if hasattr(packet.http, 'connection'):
                            request_info['connection'] = packet.http.connection
                            if 'keep-alive' in packet.http.connection.lower():
                                keepalive_connections.add(stream_id)
                        else:
                            # In HTTP/1.1, connections are keep-alive by default
                            request_info['connection'] = 'default-keepalive'
                            keepalive_connections.add(stream_id)
                        
                        http_requests_by_stream[stream_id].append(request_info)
                    
                    # HTTP Response
                    if hasattr(packet.http, 'response'):
                        if stream_id not in http_responses_by_stream:
                            http_responses_by_stream[stream_id] = []
                        
                        response_info = {
                            'time': float(packet.sniff_timestamp),
                            'status_code': getattr(packet.http, 'response_code', 'UNKNOWN')
                        }
                        
                        # Check for Connection: close header -- for other tests
                        if hasattr(packet.http, 'connection'):
                            response_info['connection'] = packet.http.connection
                            if 'close' in packet.http.connection.lower():
                                connection_close_headers += 1
                        
                        http_responses_by_stream[stream_id].append(response_info)
            
            if 'TCP' in packet and hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    retransmissions += 1
                
                # Look for ACKed unseen segment markers
                if hasattr(packet.tcp, 'analysis_ack_lost_segment') or \
                   hasattr(packet.tcp, 'analysis_acked_unseen_segment'):
                    acked_unseen_segments += 1
                
                # Look for RST+ACK packets
                if hasattr(packet.tcp, 'flags_reset') and packet.tcp.flags_reset == '1' and \
                   hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack == '1':
                    rst_ack_packets += 1
        
        except Exception as e:
            print(f"Error processing packet {i}: {e}")
    
    # Track TCP handshake states
    for stream_id, stream_data in tcp_streams.items():
        # Check if we have SYN, SYN-ACK, ACK sequence
        if 'has_syn' not in stream_data or 'has_syn_ack' not in stream_data or 'has_ack' not in stream_data:
            partial_handshakes.append(stream_id)
        else:
            complete_handshakes.append(stream_id)
    
    # Analyze idle periods and potential silent terminations
    for stream_id, stream_data in tcp_streams.items():
        if 'packet_timestamps' in stream_data and len(stream_data['packet_timestamps']) > 1:
            timestamps = sorted(stream_data['packet_timestamps'])
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if len(time_diffs) > 0:
                max_idle = max(time_diffs)
                avg_idle = sum(time_diffs) / len(time_diffs)
                idle_periods.append(max_idle)
                
                # Look for significant idle periods (could be refined)
                if max_idle > avg_idle * 5 and max_idle > 1.0: 
                    if stream_id in http_requests_by_stream:
                        silently_terminated_streams.append({
                            'stream_id': stream_id, 
                            'max_idle': max_idle,
                            'avg_idle': avg_idle,
                            'requests': len(http_requests_by_stream.get(stream_id, [])),
                            'responses': len(http_responses_by_stream.get(stream_id, []))
                        })
    
    print("\n===== FASTHTTP TCP BEHAVIOR ANALYSIS =====")
    print(f"Total TCP streams: {len(tcp_streams)}")
    print(f"Total HTTP requests: {sum(len(reqs) for reqs in http_requests_by_stream.values())}")
    print(f"Total HTTP responses: {sum(len(resps) for resps in http_responses_by_stream.values())}")
    print(f"Total RST packets: {total_rst_packets}")
    print(f"Total FIN packets: {total_fin_packets}")
    print(f"Responses with 'Connection: close' header: {connection_close_headers}")
    print(f"Keep-alive connections (explicit or implicit HTTP/1.1): {len(keepalive_connections)}")
    print(f"TCP retransmissions: {retransmissions}")
    print(f"Potentially reused connections: {len(reused_connections)}")
    print(f"TCP ACKed unseen segments: {acked_unseen_segments}")
    print(f"RST+ACK packets: {rst_ack_packets}")
    
    print("\n===== PROBLEMATIC TCP BEHAVIOR =====")
    
    # 1. RST after response without Connection: close (from other tests)
    rst_streams_after_response = set(item['stream_id'] for item in rst_after_response)
    print(f"TCP streams with RST after response: {len(rst_streams_after_response)}")
    
    # 2. Analyze TCP stream durations
    stream_durations = []
    for stream_id, data in tcp_streams.items():
        duration = data['last_packet_time'] - data['first_packet_time']
        stream_durations.append((stream_id, duration))
    
    # Sort by duration
    stream_durations.sort(key=lambda x: x[1])
    
    # Find very short-lived streams with HTTP activity
    short_streams = []
    for stream_id, duration in stream_durations:
        if duration < 0.5 and (stream_id in http_requests_by_stream or stream_id in http_responses_by_stream):
            short_streams.append((stream_id, duration))
    
    print(f"Short-lived TCP streams with HTTP activity: {len(short_streams)}")
    
    # 3. Find streams where response was interrupted (has request but no complete response)
    incomplete_streams = []
    for stream_id in http_requests_by_stream.keys():
        if stream_id not in http_responses_by_stream and stream_id in rst_streams_after_response:
            incomplete_streams.append(stream_id)
    
    print(f"Incomplete HTTP transactions (request without response, ended by RST): {len(incomplete_streams)}")
    
    # 4. Analyze timing between last response and RST for problematic connections
    timing_issues = []
    for item in rst_after_response:
        stream_id = item['stream_id']
        if stream_id in http_responses_by_stream:
            # Get the last response time
            response_times = [resp['time'] for resp in http_responses_by_stream[stream_id]]
            if response_times:
                last_response_time = max(response_times)
                # Time between last response and RST
                time_to_rst = item['time'] - last_response_time
                timing_issues.append((stream_id, time_to_rst))
    
    timing_issues.sort(key=lambda x: x[1])
    
    if timing_issues:
        print("\n===== TIMING BETWEEN RESPONSE AND RST =====")
        print("Time (seconds) between last HTTP response and RST packet:")
        
        # Group by time ranges
        time_ranges = {
            "< 0.01s": 0,
            "0.01s - 0.1s": 0,
            "0.1s - 1s": 0,
            "> 1s": 0
        }
        
        for _, time_to_rst in timing_issues:
            if time_to_rst < 0.01:
                time_ranges["< 0.01s"] += 1
            elif time_to_rst < 0.1:
                time_ranges["0.01s - 0.1s"] += 1
            elif time_to_rst < 1:
                time_ranges["0.1s - 1s"] += 1
            else:
                time_ranges["> 1s"] += 1
        
        for range_name, count in time_ranges.items():
            print(f"  {range_name}: {count} streams")
    
    # 5. Check for silent connection terminations
    if silently_terminated_streams:
        print("\n===== SILENT CONNECTION TERMINATION EVIDENCE =====")
        print(f"Found {len(silently_terminated_streams)} streams with suspicious idle periods:")
        
        for i, stream in enumerate(silently_terminated_streams[:5]):  # Show top 5
            print(f"  Stream {stream['stream_id']}:")
            print(f"    Max idle period: {stream['max_idle']:.2f} seconds")
            print(f"    Avg idle period: {stream['avg_idle']:.2f} seconds")
            print(f"    HTTP requests: {stream['requests']}")
            print(f"    HTTP responses: {stream['responses']}")
        
        # Idle period statistics
        if idle_periods:
            print(f"\nIdle period statistics across all streams:")
            print(f"  Minimum: {min(idle_periods):.2f} seconds")
            print(f"  Maximum: {max(idle_periods):.2f} seconds")
            print(f"  Average: {sum(idle_periods) / len(idle_periods):.2f} seconds")
            print(f"  Median: {statistics.median(idle_periods):.2f} seconds")
    
    # 6. FastHTTP specific connection issues
    print("\n===== POSSIBLE ISSUES =====")
    
    # Calculate percentages for better analysis
    total_streams_with_responses = len(http_responses_by_stream)
    if total_streams_with_responses > 0:
        rst_after_resp_percent = (len(rst_streams_after_response) / total_streams_with_responses) * 100
        print(f"Percentage of streams with RST after response: {rst_after_resp_percent:.2f}%")
        
        if connection_close_headers > 0:
            connection_close_percent = (connection_close_headers / sum(len(resps) for resps in http_responses_by_stream.values())) * 100
            print(f"Percentage of responses with 'Connection: close' header: {connection_close_percent:.2f}%")
        else:
            print("No 'Connection: close' headers found in any responses")
    
    # Find keep-alive connections that were RST
    keepalive_rst = keepalive_connections.intersection(rst_streams_after_response)
    if keepalive_rst:
        print(f"Keep-alive connections terminated with RST: {len(keepalive_rst)} streams")
    
    # Connection reuse analysis
    if reused_connections:
        print(f"Connections with port reuse: {len(reused_connections)}")
        print("FastHTTP may be reusing local ports for new connections after previous connections have been closed or become idle")
    
    print("\n===== CONCLUSION =====")
    silence_issue = (len(silently_terminated_streams) > 0 or 
                    (total_rst_packets > 0 and connection_close_headers == 0) or
                    (acked_unseen_segments > 0 and len(short_streams) > 0))

    if silence_issue:
        print("\nPossible Issue Evidence:")
        print(f"- {acked_unseen_segments} TCP ACKed unseen segments: Direct evidence of packets missing from capture")
        print(f"- {len(short_streams)} short-lived connections: Connections terminating abnormally")
        #print(f"- 'Connection: close' headers despite connection terminations")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "wireshark_capture_1.pcapng"
    
    analyze_fasthttp_tcp_behavior(pcap_file)