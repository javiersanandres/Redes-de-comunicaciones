'''
    practica1.py
    Muestra el tiempo de llegada de los primeros paquetes (hasta que pulses Ctrl C) a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
'''

from sqlite3 import Date
from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60



def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper
	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1

	#TODO imprimir los N primeros bytes
	
	myminbytes = min(args.nbytes, header.caplen)
	
	for i in range(0, myminbytes, 1):
		print('{:02X}'.format(data[i]), end=' ')
	print('\n')

	#Escribir el tráfico al fichero de captura con el offset temporal

	if args.interface is not False:

		header.ts.tv_sec += TIME_OFFSET
		pcap_dump(pdumper, header, data)




	
if __name__ == "__main__":
	global pdumper,args,handle
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper = None
	
	#TODO abrir la interfaz especificada para captura o la traza
	if args.tracefile is not False: 
		handle=pcap_open_offline(args.tracefile ,errbuf)
		#print( "Leemos de una traza")

		#Control de errores
		if handle is None:
			logging.error("pcap_open_offline ha fallado")
			logging.error(errbuf)
			sys.exit(-1)

	else:
		handle =pcap_open_live(args.interface,  ETH_FRAME_MAX  , PROMISC, TO_MS,  errbuf ) 

		#Control de errores
		if handle is None:
			logging.error("pcap_open_live ha fallado")
			logging.error(errbuf)
			sys.exit(-1)

		#TODO abrir un dumper para volcar el tráfico (si se ha especificado interfaz) 

		descr2= pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)

		#Obtenemos solo el tiempo en que se realiza la captura(en vivo) en segundos
		tim=str(time.time())
		time=tim.split('.')
		pdumper= pcap_dump_open(descr2, 'captura.{}.{}.pcap'.format(args.interface, time[0]) )
		
		#Control de errores
		if pdumper is None:
			logging.info("pdumper ha fallado")
			sys.exit(-1)

	
	
	
	
	ret = pcap_loop(handle,-1,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))

	
	#TODO si se ha creado un dumper cerrarlo

	pcap_close(handle)

	if pdumper is not None: #si vas por traza no habria pdumper
		pcap_dump_close(pdumper)

