'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    logging.debug('Procesando mensaje ICMP...')
    if data is None or header is None:
        logging.error('No se han mandado datos o no se ha especificado cabecera')
        return
    
    if chksum(data) != 0:
        logging.error('El checksum no es correcto')
        return
    
    type, code, icmp_id, icmp_seqnum=struct.unpack('!BBHH', data[0:2]+data[4:8])[0:4]
    logging.debug('Valor de tipo: {}'.format(type))
    logging.debug('Código: {}'.format(code))
    
    if type==ICMP_ECHO_REQUEST_TYPE:
        if sendICMPMessage(data[8:], ICMP_ECHO_REPLY_TYPE, code, icmp_id, icmp_seqnum, srcIp)==False:
            logging.error('Error mandando mensaje ICMP')
            return
        
    elif type==ICMP_ECHO_REPLY_TYPE:
        with timeLock:
            if (srcIp+icmp_id+icmp_seqnum) in icmp_send_times.keys():
                RTT=-icmp_send_times[srcIp+icmp_id+icmp_seqnum]
                RTT+=header.ts.tv_sec+header.ts.tv_usec*(10**(-6))
                logging.debug('RTT aproximado: %.3lf ms', RTT*10**3)
            else:
                logging.error('No se ha encontrado esa clave para el diccionario')

    

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''
    logging.debug('Enviando mensaje ICMP...')
    icmp_message = bytes()
    
    
    if type==ICMP_ECHO_REPLY_TYPE or type==ICMP_ECHO_REQUEST_TYPE:
        
        icmp_message=bytearray(struct.pack('!BBHHH', type, code, 0, icmp_id, icmp_seqnum))+data

        checksum=struct.pack('H', chksum(icmp_message))
        
        icmp_message[2:4]=checksum[0:2]
        
        with timeLock:
            if type==ICMP_ECHO_REQUEST_TYPE:
                icmp_send_times[dstIP+icmp_id+icmp_seqnum]=time.time()
                
    else:
        logging.error('Tipo no soportado')
        return False

    if len(icmp_message) % 2:
        icmp_message+=bytes([0])
        
    if sendIPDatagram(dstIP, icmp_message, 1)==False:
        logging.error('Error enviando datagrama IP')
        return False
   
    return True
   
def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    logging.debug('Registrando process_ICMP_message...')
    
    registerIPProtocol(process_ICMP_message, 1)
    