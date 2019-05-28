from enum import Enum
import libvirt
import logging
import os
import socket
import sys
import time
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG) # TODO

ENDIANNESS = 'little'

def itob(value, length=4):
    """ Converts an integer to a HermitCore-compatible (C) bytearray """
    return value.to_bytes(length, byteorder=ENDIANNESS, signed=True)

def uitob(value, length=4):
    """ Converts an unsigned integer to a HermitCore-compatible (C) bytearray """
    return value.to_bytes(length, byteorder=ENDIANNESS, signed=False)

def btoi(arr):
    """ Converts an bytearry to an int """
    return int.from_bytes(arr, byteorder=ENDIANNESS, signed=True)

def btoui(arr):
    """ Converts an bytearry to an unsigned int """
    return int.from_bytes(arr, byteorder=ENDIANNESS, signed=False)

def stob(s, encoding='utf-8'):
    """ Encodes a string value to an bytearray """
    return str.encode(s, encoding=encoding)

def btos(b):
    """ Decodes a bytearray to an utf-8 string """
    return bytes.decode(b)

class Syscall(Enum):
    EXIT = 0
    WRITE = 1
    OPEN = 2
    CLOSE = 3
    READ = 4
    LSEEK = 5

class Proxy():
    """
    A proxy for interation with libvirt-daemon.
    """
    LIBVIRT_URI = 'qemu:///system'
    LIBVIRT_DOMAIN_TEMPLATE = 'libvirt-domain.xml'
    LIBVIRT_NETWORK_TEMPLATE = 'libvirt-network.xml'

    XML_ENCODING = 'utf-8'

    HERMIT_MAGIC = 0x7E317

    def __init__(self):
        self.conn = None

    def connect(self, uri=LIBVIRT_URI):
        """
        Connects proxy to a running libvirt-daemon.

        Keyword arguments:
        uri -- URI of the libvirtd to connect (defaults to LIBVIRT_URI)
        """
        self.conn = libvirt.open(self.LIBVIRT_URI)
        if (self.conn is None):
            raise ConnectionError('Failed to open connection to %s' % self.LIBVIRT_URI)
        else:
            log.debug('Successfully connected to %s' % self.LIBVIRT_URI)
    
    def start_network(self, net_name):
        """
        Starts a new templated network if it doesn't exist.
        Does nothing otherwise.

        :param net_name: the networks name
        :returns: The created libvirt.virNetwork
        """
        net = None
        try:
            net = self.conn.networkLookupByName(net_name)
        except:
            # create
            try:
                root = ET.parse(self.LIBVIRT_NETWORK_TEMPLATE)
                name = root.find('./name')
                name.text = net_name

                xml_string = '<?xml version="1.0" encoding="UTF-8"?>'
                xml_string += (ET.tostring(root.getroot(), encoding=self.XML_ENCODING, method='xml')).decode(self.XML_ENCODING)
                net = self.conn.networkCreateXML(xml_string)
                if (net is None):
                    raise EnvironmentError('Network \'%s\' was not started' % net_name)
                else:
                    log.debug('Network \'%s\' was started' % net.name())


            except libvirt.libvirtError as err:
                log.error("Error creating network \'%s\':\n%s" % (net_name, err))
                raise

        return net

    def open_socket(self, domain):
        # get first ip
        log.info('Waiting for IP allocation...')
        addr = domain.interfaceAddresses(0)
        start = time.time()
        while len(addr.values()) == 0:
            if (time.time() - start) > 30:
                # timeout
                raise TimeoutError('Timeout waiting for address')
            time.sleep(.1)  # relax
            addr = domain.interfaceAddresses(0)
        first_key = next(iter(addr))
        meta_ip =  addr[first_key]['addrs'][0]['addr']
        log.debug('\'%s\' has address: %s' % (domain.name(), meta_ip))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((meta_ip, 18766))
        sock.send(itob(Proxy.HERMIT_MAGIC))
        return sock
    
    def send_metadata(self, sock, args, env):
        # args
        sock.send( itob(len(args)) )
        for arg in args:
            msg = stob(arg + '\0')
            sock.send( itob(len(msg)) )
            sock.send(msg)

        # environment
        sock.send( itob(len(env)) )
        for (k, v) in env.items():
            s = '%s=%s\0' % (k, v)
            msg = stob(s)
            sock.send( itob(len(msg)) )
            sock.send(msg)
    
    def handle_syscalls(self, sock):
        while (True):
            sysc_bytes = sock.recv(4)
            syscall = btoi(sysc_bytes)

            if (syscall == Syscall.EXIT.value):
                code_bytes = sock.recv(4)
                code = btoi(code_bytes)
                log.info('Hermit exited with code %d' % code)
                if (code == -14):
                    log.debug('Did HermitCore receive an exception?')
                break

            elif (syscall == Syscall.WRITE.value):
                fd_bytes = sock.recv(4)
                fd = btoi(fd_bytes)

                size_bytes = sock.recv(8)
                size = btoui(size_bytes)

                msg_bytes = sock.recv(size)
        
                if (fd > 2):
                    # file
                    res = -1
                    try:
                        res = os.write(fd, msg_bytes)   # FIXME rewrite - 8chars
                    except:
                        log.error('Could not write to fd %d' % fd)
                        break
                    
                    # send bytes written
                    res_bytes = itob(res, 8)
                    sock.send(res_bytes)
                else:
                    # stdio
                    sent = 0
                    while (sent < size):
                        res = 0
                        try:
                            res = os.write(fd, msg_bytes[sent:])
                        except:
                            res = -1

                        if (res < 0):
                            log.error('Could not write to fd %d' % fd)
                            sock.close()
                            return
                        sent += res

            elif (syscall == Syscall.OPEN.value):
                size_bytes = sock.recv(8)
                size = btoui(size_bytes)

                name_bytes = sock.recv(size)
                name_bytes = name_bytes[:size-1]

                flags_bytes = sock.recv(4)
                flags = btoi(flags_bytes)

                mode_bytes = sock.recv(4)
                mode = btoi(mode_bytes)
                
                fd = -1
                try:
                    fd = os.open(name_bytes, flags, mode)
                except Exception as ex:
                    log.error('Error opening file:\n%s' % ex)
                fd_bytes = itob(fd)
                sock.send(fd_bytes)

            elif (syscall == Syscall.CLOSE.value):
                fd_bytes = sock.recv(4)
                fd = btoi(fd_bytes)

                res = 0
                if (fd > 2):    # do not close our stdio
                    try:
                        os.close(fd)
                    except:
                        res = 1 # TODO should be EOF
                        log.debug('Error closing fd: %d' % fd)
                res_bytes = itob(res)
                sock.send(res_bytes) 

            elif (syscall == Syscall.READ.value):
                fd_bytes = sock.recv(4)
                fd = btoi(fd_bytes)

                size_bytes = sock.recv(8)
                size = btoui(size_bytes)

                res = -1
                data = None
                try:
                    data = os.read(fd, size)
                    res = len(data)
                except:
                    log.error('Error reading from fd %d' % fd)

                # send result (signed)
                res_bytes = itob(res, 8)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
                sock.send(res_bytes)
                if (res > 0):
                    # send data
                    sock.send(data)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            elif (syscall == Syscall.LSEEK.value):
                fd_bytes = sock.recv(4)
                fd = btoi(fd_bytes)

                pos_bytes = sock.recv(8)
                pos = btoi(pos_bytes)

                how_bytes = sock.recv(4)
                how = btoi(how_bytes)

                res = -1
                try:
                    res = os.lseek(fd, pos, how)
                except:
                    log.error('Error seeking on fd %d' % fd)
                
                # send result
                res_bytes = itob(res, 8)
                sock.send(res_bytes)

            else:
                log.error('Received unknown syscall %d' % syscall)
                break


        sock.close()        
    
    def create(self, hermit_image):
        """
        Starts a new templated instance if it doesn't exist.
        Does nothing otherwise.

        :param hermit_image: the image to start
        :param args: the instance start-arguments
        :param env: the instance environment
        :returns: the created libvirt.virDomain
        """
        root = ET.parse(self.LIBVIRT_DOMAIN_TEMPLATE)
        domain_name = root.find('./name')
        if (domain_name is None):
            raise AttributeError('Couldn\'t find domain-name in xml')
        domain_name = domain_name.text

        e_image = root.find('./os/initrd')
        e_image.text = hermit_image

        if (not os.path.isfile(hermit_image)):
            raise FileNotFoundError('Image \'%s\' is not valid. Is the path correct?' % hermit_image)
        
        log.debug('Image: %s' % hermit_image)

        domain = None
        created = False

        try:
            domain = self.conn.lookupByName(domain_name)
            log.info('Instance \'%s\' already exists' % domain.name())
            return domain
        except:
            pass    # libvirt already logs the error

        try:
            # ensure all referred networks exist
            ifaces = root.findall('./devices/interface[@type=\'network\']')
            for iface in ifaces:
                net_name = iface.find('./source').attrib['network']
                self.start_network(net_name)

            # create instance
            xml_string = '<?xml version="1.0" encoding="UTF-8"?>'
            xml_string += (ET.tostring(root.getroot(), encoding=self.XML_ENCODING, method='xml')).decode(self.XML_ENCODING)
            domain = self.conn.createXML(xml_string, 0)
            if (domain is None):
                raise EnvironmentError('Domain \'%s\' was not started' % domain_name)
            log.debug('Domain \'%s\' was started' % domain.name())

        except Exception as ex:
            log.error('Error creating domain \'%s\':\n%s' % (domain_name, ex))
            raise        

        return domain
    
    def run(self, domain, args=[], env={}):
        # open HermitCore socket
        sock = self.open_socket(domain)

        # send ENV & args
        self.send_metadata(sock, args, env)

        # syscall-loop
        self.handle_syscalls(sock)

        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        log.error('No HermitCore-Image specified')
        log.error('Usage: proxy.py <IMAGE> [args...]')
        exit(1)

    proxy = Proxy()
    proxy.connect()
    try:
        domain = proxy.create(sys.argv[1])
    except Exception as ex:
        log.error('Error creating instance: %s' % ex)
        exit(1)

    try:
        proxy.run(domain, 
            args=sys.argv[1:],
            env=os.environ
            )
    except KeyboardInterrupt:
        log.warn("Keyboard interrupt")
    
    # remove instance
    domain.destroy()
    log.info("Destroyed instance")