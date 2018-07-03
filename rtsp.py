#!/usr/bin/python

import argparse
import logging
import logging.handlers
import os
import re
import select
import socket
import struct
import sys

socket.SO_ORIGINAL_DST = 80

def log():
    return logging.getLogger(__file__)

class RTPTransform():
    def __init__(self, id, client, server):
        self.id = id
        self.client = client
        self.server = server
        self.client_port = None

    def fromClient(self, packet):
        rc = []
        for line in packet.split('\r\n'):
            m = re.match('\ATransport: RTP/AVPF/UDP;unicast;destination=\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3};client_port=(?P<port>\d+)\Z', line)
            if not m:
                rc.append(line)
            else:
                transport = 'Transport: RTP/AVPF/UDP;unicast;client_port=%s' % m.group('port')
                log().info('[%s] >> %s', self.id, line)
                log().info('[%s] => %s', self.id, transport)
                rc.append(transport)
                self.client_port = int(m.group('port'))
        return '\r\n'.join(rc)

    def fromServer(self, packet):
        return packet

    def clientPort(self):
        return self.client_port

class Forward():
    def __init__(self, client, addr, port, transform):
        self.id = '%s:%s' % (addr, port)

        self.client = {}
        self.client['socket'] = client
        self.client['addr'] = addr
        self.client['port'] = port
        self.client['mapped'] = False

        self.server = {}

        self.client['socket'].setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        sockaddr_in = self.client['socket'].getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, 16)
        self.server['port'], server_ip = struct.unpack('!2xH4s8x', sockaddr_in)
        self.server['addr'] = socket.inet_ntoa(server_ip)

        log().info('[%s] server %s:%s', self.id, self.server['addr'], self.server['port'])

        try:
            self.server['socket'] = socket.socket()
            self.server['socket'].connect((self.server['addr'], self.server['port']))
        except Exception as e:
            log().warning('[%s] %s', self.id, str(e))
            self.client.close()
            log().info('[%s] closed', self.id)
            return False

        self.transform = transform(self.id, self.client, self.server)

    def sockets(self):
        return [self.client['socket'], self.server['socket']]

    def forward(self, s, packet):
        if not packet:
            self.terminate()
        else:
            if s == self.client['socket']:
                self.server['socket'].send(self.transform.fromClient(packet))
            else:
                self.client['socket'].send(self.transform.fromServer(packet))

    def clientPort(self):
        return self.transform.clientPort()

    def isMapped(self):
        return self.client['mapped']

    def setMapped(self, mapped):
        self.client['mapped'] = mapped

    def connectionId(self):
        return self.id

    def clientAddr(self):
        return self.client['addr']

    def serverAddr(self):
        return self.server['addr']

    def terminate(self):
        self.client['socket'].close()
        self.server['socket'].close()
        log().info('[%s] closed', self.id)

class Proxy():
    def __init__(self, addr, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.server.bind((addr, port))
        self.connections = []

    def loop(self):
        self.server.listen(5)
        while True:
            sockets = [self.server] + [s for c in self.connections for s in c.sockets()]
            inputready, _, _ = select.select(sockets, [], [])
            for i in inputready:
                if i == self.server:
                    client, (addr, port) = i.accept()
                    f = Forward(client, addr, port, RTPTransform)
                    if f:
                        self.connections.append(f)
                else:
                    for c in self.connections:
                        s = c.sockets()
                        if i == s[0] or i == s[1]:
                            try:
                                p = i.recv(4096)
                            except Exception as e:
                                p = None

                            if p:
                                c.forward(i, p)
                                if c.clientPort() and not c.isMapped():
                                    log().info('iptables add: %s:10000 to %s:%s', c.serverAddr(), c.clientAddr(), c.clientPort())
                                    os.system('/usr/sbin/iptables -A PREROUTING -i eth0.10 -t nat -p udp -s %s --sport 10000 --dport %s -j DNAT --to %s' % (c.serverAddr(), c.clientPort(), c.clientAddr()))
                                    c.setMapped(True)
                            else:
                                if c.clientPort() and c.isMapped():
                                    log().info('iptables del: %s:10000 to %s:%s', c.serverAddr(), c.clientAddr(), c.clientPort())
                                    os.system('/usr/sbin/iptables -D PREROUTING -i eth0.10 -t nat -p udp -s %s --sport 10000 --dport %s -j DNAT --to %s' % (c.serverAddr(), c.clientPort(), c.clientAddr()))
                                    c.setMapped(False)
                                self.connections.remove(c)
                            break

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=554,
                        help='Listen on port (default: %(default)s).')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if not args.foreground:
        pid = os.fork()
        if pid != 0:
            return 0
        os.setsid()
        os.close(sys.stdin.fileno())

    logger = logging.getLogger()
    syslog_handler = logging.handlers.SysLogHandler()
    syslog_handler.setFormatter(logging.Formatter(fmt='%(name)s[%(process)d] %(levelname)s: %(message)s'))
    logger.addHandler(syslog_handler)

    if args.foreground:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
        logger.addHandler(stream_handler)

    if args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARN)

    p = Proxy('', args.port)
    p.loop()

if __name__ == '__main__':
    sys.exit(main())

