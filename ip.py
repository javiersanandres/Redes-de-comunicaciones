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
import threading
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}

#Diccionario de cabeceras en caso de fragmentación
headers={}
assemble_Lock=Lock()

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


    
    version=(data[0] & 0xF0) >> 4  
    IHL= (data[0] & 0x0F) << 2
    type_of_service=data[1]
    total_length, identification=struct.unpack('!HH', data[2:6])[0:2]
    flags=(data[6] & 0xE0) >> 5
    offset=((data[6] & 0x1F) << 8 | data[7])
    time_to_live=data[8]
    protocol=data[9]
    header_checksum, srcIP, destIP=struct.unpack('!HII', data[10:20])[0:3]

    if IHL>IP_MIN_HLEN:
        options=data[20:IHL]

    if IHL<IP_MIN_HLEN or IHL>IP_MAX_HLEN:
        logging.error('Tamaño de cabecera IP incorrecto')
        return
    
    if chksum(data[:IHL]) != 0:
        logging.error('Error en el checksum')
        return     
    
    if (flags & 0x02) or (flags & 0x04):
        logging.error('Flags no válidas')
    
    if version != 4:
        logging.error('Version {} no reconocida'.format(version))
    
    if type_of_service != 0x16:
        logging.error('No se reconoce el tipo de servicio')
        
    
    if offset==0:
        logging.debug('Longitud de la cabecera IP: {}'.format(IHL))
        logging.debug('IPID: {}'.format(identification))
        logging.debug('TTL: {}'.format(time_to_live))
        logging.debug('DF={} y MF={}'.format(flags & 0x02, flags & 0x01))
        logging.debug('Valor de offset (sin multiplicar por 8): {}'.format(offset))
        logging.debug('Valor de offset (multiplicado por 8): {}'.format(offset << 3))
        logging.debug('IP Origen: {}.{}.{}.{}'.format(data[12],data[13], data[14], data[15]))
        logging.debug('IP Destino: {}.{}.{}.{}'.format(data[16],data[17], data[18], data[19]))
        logging.debug('Protocolo: {}'.format(protocol))


    if protocol not in protocols.keys():
        logging.error('El protocolo no ha sido registrado')
        return

    if (flags & 0x01)==0 and offset==0:
        protocols[protocol](us, header, data[IHL:total_length], srcIP)
        return
    
    reassembleIPDatagram(us, header, protocol, identification, offset << 3, flags & 0x01, data[IHL:total_length], srcIP)


def reassembleIPDatagram(us, header, protocol, identification, offset, MF, data, srcIP):
    '''
        Nombre: reassembleIPDatagram
        Descripción: Esta función se encarga de reensamblar los fragmentos de un datagrama I
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -protocol: número de protocolo de nivel superior.
            -identification: entero de 16 bits que contiene el identificador del datagarma IP
            -offset: entero que indica el número de offset del datagrama
            -MF: bandera que indica si es el último fragmento (bandera a 0) o si no (bandera a 1)
            -data: array de bytes con el contenido del datagrama IP
            -srcIP: entero de 32 bits con la IP de quien ha enviado el datagrama
        Retorno: Ninguno
    '''

    with assemble_Lock:

        if MF==0 and headers.get((identification, srcIP)):
                headers[(identification, srcIP)][-1]=1

        if headers.get((identification, srcIP)) is None:

            headers[(identification, srcIP)]={}
            headers[(identification, srcIP)][offset]=data
            headers[(identification, srcIP)][-1]=0

            if MF==0:
                headers[(identification, srcIP)][-1]=1

            threading.Thread(target=discardIPDatagram, args=(identification, srcIP)).start()
            
        elif headers.get((identification, srcIP)) is not None:

            headers[(identification, srcIP)][offset]=data

            if headers[(identification, srcIP)][-1]==1:
                
                sorted_keys=sorted(headers[(identification, srcIP)])

                offset_controller=len(headers[(identification, srcIP)][sorted_keys[1]])

                if sorted_keys[1]==0 and all([(sorted_keys[i+1]-sorted_keys[i])==offset_controller for i in range(1, len(sorted_keys)-1)]):
                    
                    aux=bytes()
                    for i in sorted_keys[1:]:
                        aux+=headers[(identification, srcIP)][i]
                    del headers[(identification, srcIP)]

                    protocols[protocol](us, header, aux, srcIP)


def discardIPDatagram(identification, srcIP):
    '''
        Nombre: discardIPDatagram
        Descripción: Esta función espera 1 segundo desde que se envía el último fragmento con un IPID y srcIP determinados. Si en ese tiempo el datagrama IP
        no se ha reensamblado y, por ende, enviado; entonces, eso significa que se han perdido fragmentos y la función se encarga de descartar el datagrama.
        Argumentos:
            -srcIP: entero de 32 bits con la IP de quien ha enviado el datagrama
            -identification: entero de 16 bits que contiene el identificador del datagarma IP
        Retorno: Ninguno
          
    '''
    srcIP_format=struct.pack('!I', srcIP)
    index=(identification, srcIP)

    with assemble_Lock:
        length_o=len(headers.get(index))
    
    time.sleep(1)

    with assemble_Lock:
        if headers.get(index) is not None:
            length_f=len(headers.get(index))
        else:
            return

    while length_o != length_f:

        with assemble_Lock:
            if headers.get(index) is not None:
                length_o=len(headers.get(index))
            else:
                return
    
        time.sleep(1)

        with assemble_Lock:
            if headers.get(index) is not None:
                length_f=len(headers.get(index))
            else:
                return

    logging.debug('Esperando a que lleguen el resto de fragmentos para el IPID = {} e IP = {}.{}.{}.{}'.format(identification, srcIP_format[0], srcIP_format[1], srcIP_format[2], srcIP_format[3]))

    with assemble_Lock:
        if headers.get(index) is not None:
            logging.debug('Faltan fragmentos: datagrama descartado')
            del headers[index]


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
    global myIP, MTU, netmask, defaultGW, ipOpts, IPID
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


    if opts is not None:
        ipOpts=opts
        length=len(ipOpts)
        if length % 4 or length>40:
            logging.error('Tamaño de opciones inválido')
            return False
    else:
        ipOpts=None
    
    registerCallback(process_IP_datagram, 0x0800)
    IPID=11
    
    return True
    

def sendIPDatagram(dstIP,data,protocol):
    global IPID, MTU, ipOpts, myIP, netmask, defaultGW
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
    ip_header_temp = bytes()
    ip_header=[]
       
    if data is None or protocol is None:
        return False
    
    if ipOpts is None:
        ipOpts=bytes()       
    
    length=len(data)
    header_length=20+len(ipOpts)

    if length<=MTU-header_length:
        ip_header_temp=bytearray(struct.pack('!BBHHHBBHII', 0x40 | header_length//4, 0x16, length+header_length, IPID, 0, 128, protocol, 0, myIP, dstIP)+ipOpts)

        checksum=struct.pack('H', chksum(ip_header_temp))      
        
        ip_header_temp[10:12]=checksum[0:2]

        ip_header.append(ip_header_temp+data)
    
    else:

        max_length=(MTU-header_length)-(MTU-header_length)%8
        i=0
        offset=0

        while length-max_length>0:
            ip_header_temp=bytearray(struct.pack('!BBHHHBBHII', 0x40 | header_length//4, 0x16, max_length+header_length, IPID, (0x20 << 8) | offset, 128, protocol, 0, myIP, dstIP)+ipOpts)

            checksum=struct.pack('H', chksum(ip_header_temp))
            
            ip_header_temp[10:12]=checksum[0:2]

            ip_header.append(ip_header_temp+data[offset*8:offset*8+max_length])

            length-=max_length
            offset+=max_length//8
            i+=1

        ip_header_temp=bytearray(struct.pack('!BBHHHBBHII', 0x40 | header_length//4, 0x16, length+header_length, IPID, offset, 128, protocol, 0, myIP, dstIP)+ipOpts)
        
        checksum=struct.pack('H', chksum(ip_header_temp))
            
        ip_header_temp[10:12]=checksum[0:2]

        ip_header.append(ip_header_temp+data[offset*8:offset*8+length])
            

    if (dstIP & netmask) != (myIP & netmask):
        dstMac=ARPResolution(defaultGW)
    else:
        dstMac=ARPResolution(dstIP)

    if dstMac is None:
        logging.error('No se ha encontrado dirección MAC para dicha dirección IP')
        return False
    
    
    for i in range(0, len(ip_header)):
        if sendEthernetFrame(ip_header[i], struct.unpack('!H', ip_header[i][2:4])[0], 0x0800, dstMac)==-1:
            logging.error('Error enviando datagrama a nivel Ethernet')
            return False
        
    IPID+=1

    return True
    
    
        
        
        
    
    
    
    
    
    



