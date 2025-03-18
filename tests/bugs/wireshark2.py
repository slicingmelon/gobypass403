import pyshark
import collections
import sys
from datetime import datetime

def analyze_fasthttp_tcp_behavior(pcap_file):
    print(f"Analyzing FastHTTP TCP behavior in {pcap_file}...")
    
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)
    
    # Track TCP streams instead of individual connections
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
    
    # Process each packet
    for i, packet in enumerate(cap):
        # Status update
        if i % 10000 == 0 and i > 0:
            print(f"Processed {i} packets...")
        
        try:
            if 'TCP' in packet:
                # Track TCP stream ID for correlation
                stream_id = packet.tcp.stream
                
                # Track TCP handshake
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    if stream_id not in tcp_streams:
                        tcp_streams[stream_id] = {}
                    tcp_streams[stream_id]['has_syn'] = True
                    
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
                
                # Track TCP streams
                if stream_id not in tcp_streams:
                    tcp_streams[stream_id] = {
                        'packets': 0,
                        'first_packet_time': float(packet.sniff_timestamp),
                        'last_packet_time': float(packet.sniff_timestamp)
                    }
                else:
                    tcp_streams[stream_id]['last_packet_time'] = float(packet.sniff_timestamp)
                
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
                        
                        # Check for keep-alive header
                        if hasattr(packet.http, 'connection'):
                            request_info['connection'] = packet.http.connection
                            if 'keep-alive' in packet.http.connection.lower():
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
                        
                        # Check for Connection: close header
                        if hasattr(packet.http, 'connection'):
                            response_info['connection'] = packet.http.connection
                            if 'close' in packet.http.connection.lower():
                                connection_close_headers += 1
                        
                        http_responses_by_stream[stream_id].append(response_info)
            
            if 'TCP' in packet and hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    retransmissions += 1
        
        except Exception as e:
            print(f"Error processing packet {i}: {e}")
    
    # Track TCP handshake states
    for stream_id, stream_data in tcp_streams.items():
        # Check if we have SYN, SYN-ACK, ACK sequence
        if 'has_syn' not in stream_data or 'has_syn_ack' not in stream_data or 'has_ack' not in stream_data:
            partial_handshakes.append(stream_id)
        else:
            complete_handshakes.append(stream_id)
    
    # Analysis of results
    print("\n===== FASTHTTP TCP BEHAVIOR ANALYSIS =====")
    print(f"Total TCP streams: {len(tcp_streams)}")
    print(f"Total HTTP requests: {sum(len(reqs) for reqs in http_requests_by_stream.values())}")
    print(f"Total HTTP responses: {sum(len(resps) for resps in http_responses_by_stream.values())}")
    print(f"Total RST packets: {total_rst_packets}")
    print(f"Total FIN packets: {total_fin_packets}")
    print(f"Responses with 'Connection: close' header: {connection_close_headers}")
    print(f"Keep-alive connections: {len(keepalive_connections)}")
    print(f"TCP retransmissions: {retransmissions}")
    
    # Analyze potentially problematic scenarios
    print("\n===== PROBLEMATIC TCP BEHAVIOR =====")
    
    # 1. RST after response without Connection: close
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
    
    # Sort by timing
    timing_issues.sort(key=lambda x: x[1])
    
    # Show some samples
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
    
    # 5. Check for very quick RST after SYN-ACK (connection rejected)
    # This would need more packet-level timing analysis
    
    # 6. FastHTTP specific connection issues
    print("\n===== FASTHTTP SPECIFIC ISSUES =====")
    
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
    
    # Final conclusion
    print("\n===== CONCLUSION =====")
    if total_rst_packets > 0 and connection_close_headers == 0:
        print("ISSUE IDENTIFIED: TCP connections are being terminated with RST packets without")
        print("proper 'Connection: close' headers in the HTTP responses.")
        print("\nThis matches the FastHTTP error: 'the server closed connection before returning")
        print("the first response byte. Make sure the server returns 'Connection: close' response")
        print("header before closing the connection'")
        
        print("\nPOTENTIAL ROOT CAUSE:")
        print("1. The server may be hitting connection limits and forcibly closing connections")
        print("2. FastHTTP's connection pooling may conflict with server connection management")
        print("3. TCP keep-alive connections might be timing out at the server level")
        
        if len(short_streams) > 0:
            print("\nThere are also short-lived TCP connections that may indicate connection")
            print("rejection or premature termination by the server.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "wireshark_capture_1.pcapng"
    
    analyze_fasthttp_tcp_behavior(pcap_file)