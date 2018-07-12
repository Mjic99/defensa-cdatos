# -*- coding:utf-8 -*-
# Parte del código y la librería aioarping fueron desarrollados por el autor de
# abajo, y se hace uso justo de ellos para los fines de este proyecto. Es por
# esto que se añade el siguiente aviso de copyright
#
# Copyright (c) 2017 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.

import subprocess, asyncio, aioarping, ipaddress, sqlite3
from db_manager import *

inicializar()

def guardar_info(data):
	print ("Source MAC:      {}".format(data["mac"]))
	print ("Source IP:       {}".format(data["ip"]))
	if buscar_dir(str(data["ip"])):
		print("En base de datos\n")
		pass
	else:
		guardar_dir(data)
		print("Agregado\n")

def check_intrusos(data):
	print ("Source MAC:      {}".format(data["mac"]))
	print ("Source IP:       {}".format(data["ip"]))
	if buscar_dir(str(data["mac"])):
		print("Dispositivo registrado\n")
		pass
	else:
		print("Dispositivo no registrado, bloqueado\n")
		bloquear_in(data["mac"])
		bloquear_out(data["ip"])

def bloquear_in(mac):
	subprocess.call(["sudo", "/sbin/iptables", "-A", "INPUT", "-m", "mac", "--mac-source", str(mac), "-j", "DROP"])
def bloquear_out(ip):
	subprocess.call(["sudo", "iptables", "-A", "OUTPUT", "-d", str(ip), "-j", "DROP"])
    
event_loop = asyncio.get_event_loop()
mydomain=[x for x in subprocess.getoutput("ip route|sed '/via/d' | sed '/src /!d' | sed '/dev /!d' |sed '2,$d'").split(" ") if x]
myiface=mydomain[2]/sbin/iptables -A INPUT -m mac --mac-source 00:0F:EA:91:04:08 -j DROP
mydomain=mydomain[0]

#First create and configure a raw socket
mysocket = aioarping.create_raw_socket(myiface)

#create a connection with the raw socket
fac=event_loop._create_connection_transport(mysocket, aioarping.ArpRequester, None, None)
#Start it
conn,arpctrl = event_loop.run_until_complete(fac)

def registro():
	#Attach your processing 
	arpctrl.process=guardar_info
	print ("Red {} en interfaz {}".format(mydomain,myiface))
	#Probe
	arpctrl.request(ipaddress.IPv4Network(mydomain))

	#Cerrar en 5 segundos
	async def slow_operation(future):
	    await asyncio.sleep(5)
	    future.set_result('Tiempo cumplido')

	future = asyncio.Future()
	asyncio.ensure_future(slow_operation(future))
	event_loop.run_until_complete(future)

def deteccion():
	arpctrl.process=check_intrusos
	print ("Red {} en interfaz {}".format(mydomain,myiface))
	arpctrl.request(ipaddress.IPv4Network(mydomain))
	try:
		event_loop.run_forever()
	except KeyboardInterrupt:
		print('keyboard interrupt')
	finally:
		print('Cerrando loop')
		conn.close()
		event_loop.close()
		on_exit()

while True:
	print('''Opciones:
		R: Registrar dispositivos
		D: Detección de intrusos
		L: Limpiar base de datos''')
	ans = input("¿Qué desea hacer? ")
	if ans.lower()=="r":
		registro()
		break
	elif ans.lower()=="d":
		deteccion()
		break
	elif ans.lower()=="l":
		limpiar()
		break
	else:
		print("Respuesta no válida")
		continue