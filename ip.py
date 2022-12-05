'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0x07E6       
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    logging.debug('Procesando Datagrama IP...')
    
    if header is None or data is None or srcMac is None:
        logging.error('La cabecera, el datagrama o la mac de origen son None')
        return
    
    version=data[0] & 0xF0
    IHL= (data[0] & 0x0F) << 2
    type_of_service=data[1]
    total_length=data[2:4]
    identification=struct.unpack('H', data[4:6])[0]
    flags=data[6] & 0xE0
    offset=((data[6] & 0x1F) << 8 | data[7]) << 3
    time_to_live=data[8]
    protocol=data[9]
    header_checksum=struct.unpack('!H', data[10:12])[0]
    srcIP=struct.unapck('!I', data[12:16])[0]
    destIP=struct.unpack('!I', data[16:20])[0]
    
    if IHL>IP_MIN_HLEN:
        options=data[20:IHL]
    
    if header_checksum != 0:
        logging.error('Error en el checksum')
        return
    
    if (flags & 0x02) != 0 or (flags & 0x04):
        logging.error('Flags no válidas')
        return
    
    if version != 4:
        logging.error('Versión no reconocida')
        return
    
    if type_of_service != 0x16:
        logging.error('No se reconoce el tipo de servicio')
        return
    
    if IHL<IP_MIN_HLEN or IHL>IP_MAX_HLEN:
        logging.error('Tamaño de cabecera IP incorrecto')
        
    
    
    logging.debug('Longitud de la cabecera IP: {}¡'.format(IHL.hex()))
    logging.debug('IPID: {}'.format(IHL.hex()))
    logging.debug('TTL: {}'.format(time_to_live.hex()))
    logging.debug('DF={} y MF={}'.format(flags & 0x02, flags & 0x01))
    logging.debug('Valor de offset: {}'.format(offset.hex()))
    logging.debug('IP Origen: {}'.format(srcIP))
    logging.debug('IP Destino: {}'.format(destIP))
    logging.debug('Protocolo: {}'.format(protocol.hex()))

    if protocol not in protocols.keys():
        logging.error('El protocolo no ha sido registrado')
        return
    
    protocols[protocol](us, header, data[IHL:], srcIP)




def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    
    logging.debug('Registrando Protocolo IP...')
    if callback is None:
        logging.error('La función a registrar es None o no se ha especificado protocolo')
        return
    
    if protocol in protocols.keys():
        logging.debug('Función ya registrada') #No lo consideramos como un error simplemente ya está registrada
        return

    protocols[protocol]=callback



def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    if initARP(interface)==-1:
        return False
    
    myIP=getIP(interface)
    MTU=getMTU(interface)
    netmask=getNetmask(interface)
    defaultGW=getDefaultGW(interface)
    
    length=len(ipOpts)
    if length/4 or length>40:
        logging.error('Tamaño de opciones inválido')
        return False
    
    ipOpts=opts
    
    registerCallback(process_IP_datagram, 0x0800)
    IPID=11
    return True
    

def sendIPDatagram(dstIP,data,protocol):
    global IPID, MTU, opts, myIP
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    logging.debug('Enviando datagrama IP...')
    ip_header_init = bytes()
    temp=bytes()
    ip_header=[]
       
    if data is None and protocol is None:
        return False
    
    
    if opts is None:
        ip_header_init=bytes([0x45])+bytes([0x16])
    else:
        ip_header_init=bytes([0x40 | (20+len(opts))/4])+bytes([0x16])
    
    ip_header_final=bytes([128])+bytes([protocol])+bytes([0x00, 0x00])+struct.pack('!I', myIP)+struct.pack('!I', dstIP)+opts
    
    length=len(data)
    if length<=MTU-20:
        ip_header_init+=struct.pack('H', length+(ip_header_init[0] & 0x0F))+struct.pack('H', IPID)+bytes([0x00])+bytes([128])+ip_header_final
        ip_header_init[10:12]=struct.pack('!H', chksum(ip_header_init))
        ip_header.append(ip_header_init)
    else:
        max_length=(MTU-20)-(MTU-20)%8
        i=0
        offset=0
        while length-max_length>0:
            temp=ip_header_init+struct.pack('H', max_length+(ip_header_init[0] & 0x0F))+struct.pack('H', IPID+i)+bytes([0x20 | offset])+ip_header_final
            temp[10:12]=struct.pack('!H', chksum(temp))
            ip_header.append(temp+data[offset*8:offset*8+max_length])
            length-=max_length
            offset+=max_length/8
            i+=1
        temp=ip_header_init+struct.pack('H', length+(ip_header_init[0] & 0x0F))+struct.pack('H', IPID+i)+bytes([offset])+ip_header_final
        temp[10:12]=struct.pack('!H', chksum(temp))
        ip_header.append(temp+data[offset*8:offset*8+length])
        
    return True
    
    
        
        
        
    
    
    
    
    
    



