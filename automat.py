import subprocess
import sys
import os
import matplotlib.pyplot as plt

def limpiarPantalla():os.system('clear')

def validar_opciones():
	if ('b' in procesos) or ('c' in procesos) or ('d' in procesos) or ('e' in procesos) or ('f' in procesos) or ('g' in procesos):
		return True 
	else: 
		return False

def append_to_a_text(direccion,frase):
	archivo = open(direccion,'a+')
	archivo.write('\n------------------------------\n'+frase+'\n------------------------------\n')
	archivo.close()


def diccionarioDeIps(archivo):
	target_ips = []

	subprocess.call('cp ./'+carpeta+'/'+archivo+' ./'+carpeta+'/only-hosts-ips.txt', shell=True)

	ips = open('./'+carpeta+'/only-hosts-ips.txt','r')
	lineas = ips.readlines()
	ips.close()

	ips = open('./'+carpeta+'/only-hosts-ips.txt','w')
	for linea in lineas:
		if("Nmap scan report for " in linea):
			linea=linea.replace("Nmap scan report for ","")
			ips.write(linea)
			linea_split = linea.split(' ')
			if len(linea_split) > 1:
				ip=linea_split[1]
				ip=ip.replace('(','')
				ip=ip.replace(')','')
				ip=ip.replace('\n','')
				target_ips.append({'Nombre':linea_split[0],'Ip':ip})
			else:
				linea_split[0]=linea_split[0].replace('\n','')
				target_ips.append({'Nombre':linea_split[0],'Ip':linea_split[0]})
	ips.close()
	return target_ips


def graficar(direccion):
	scores=[]
	labels_q=['Baja','Media','Alta','Critica']
	scores_q=[0,0,0,0]
	explode = [0, 0, 0.1, 0.15]
	colors=['#198754','#ffc107','#fd7e14','#dc3545']

	archivo = open(direccion,'r')
	lineas = archivo.readlines()
	archivo.close()

	for linea in lineas:
		if("|     	" in linea):
			linea=linea.split('\t')
			scores.append(linea[2])
			scores=[float(i) for i in scores]


	if len(scores) > 1:
		for i in scores:
			if (i>=0.1) and (i<=3.9): 
				scores_q[0]+=1
			elif (i>=4.0) and (i<=6.9): 
				scores_q[1]+=1 
			elif (i>=7.0) and (i<=8.9): 
				scores_q[2]+=1
			elif (i>=9.0) and (i<=10.0): 
				scores_q[3]+=1

		for i in range(0,len(scores_q)-1):
			if scores_q[i] == 0: 
				scores_q.pop(i)
				labels_q.pop(i)
				explode.pop(i) 

		plt.pie(scores_q, labels=labels_q,explode=explode, autopct= lambda p: '{:.2f}% ({:.0f})'.format(p,(p/100)*sum(scores_q), shadow=True, startangle=90,colors=colors))
		plt.title('Estadisticas de Vulnerabilidades (TOTAL: '+str(sum(scores_q))+')')
		plt.savefig(direccion+'.png')



if len(sys.argv)>1:
	target=sys.argv[1]
	if ',' in target:
		target=target.replace(',',' ')
	limpiarPantalla()
else:

	while True:
		limpiarPantalla()
		print("\n___________________________________")
		print("- Single IP\t x.x.x.x")
		print("- Multiple IPs\t x.x.x.x x.x.x.x")
		print("- Rango de IPs\t x.x.x.1-254")
		print("- Dominio\t ejemplo.com")
		print("- Rango de IPs con mascara\t x.x.x.x/x")
		print("- Ips en un archivo de texto\t archivo.txt")
		print("___________________________________\n")
		target = input("Por favor Ingrese el target: ")
		if target:
			limpiarPantalla()
			break

while True:
	print('\nEL TRGET ES: '+target)

	print("___________________________________")
	print("a - Descubrimiento de Hosts")
	print("b - Escaneo puertos UDP")
	print("c - Escaneo puertos TCP SYN")
	print("d - SO y Escaneo de puertos + version del servicio que corren")
	print("e - Busqueda de Vulnerabilidades")
	print("f - Enumeracion de NetBios")
	print("g - Enumeracion de DNS\n")
	print("Default (dejar en blanco) - Todas las anteriores")
	print("___________________________________\n")
	procesos = input("Ingrese consecutivamente las letras de los escaneos a realizar (ex: ade): ")
	
	if not procesos:
		procesos = 'abcdef'
	
	if ('a' in procesos) or validar_opciones():
		while True:
			carpeta=input('\nIngrese un nombre para la carpeta donde se guardaran los reportes: ')
			if carpeta:
				break
		if not os.path.exists('./'+carpeta):
			os.makedirs('./'+carpeta)
		break
	else:
		limpiarPantalla()
		print('\nPOR FAVOR INGRESE UNA OPCION VALIDA')


if 'a' in procesos:
	print('____________________________\nDESCUBRIMIENTO DE HOSTS\n____________________________')
	archivo = 'decubrimiento-hosts.ip'
	if('.txt' in target):
		subprocess.call('sudo nmap -sn -iL '+target+' -oN ./'+carpeta+'/'+archivo, shell=True)
	else:	
		subprocess.call('sudo nmap -sn '+target+' -oN ./'+carpeta+'/'+archivo, shell=True)
else:
	print('____________________________\nLISTANDO HOSTS\n____________________________')
	archivo = 'lista-hosts.ip'
	if('.txt' in target):
		subprocess.call('sudo nmap -sL -iL '+target+' -oN ./'+carpeta+'/'+archivo , shell=True)
	else:
		subprocess.call('sudo nmap -sL '+target+' -oN ./'+carpeta+'/'+archivo , shell=True)

target_ips = diccionarioDeIps(archivo)

if validar_opciones():
	for item_of_targets in target_ips:
		target_folder_name=item_of_targets['Nombre'].replace(".","_")
		if not os.path.exists('./'+carpeta+'/'+target_folder_name):
				os.makedirs('./'+carpeta+'/'+target_folder_name)

		if 'b' in procesos:
			print('\n____________________________\n\nESCANEO UDP DE: '+item_of_targets['Nombre']+'\n____________________________')
			subprocess.call('sudo nmap -sU -p1-200 -v '+item_of_targets['Ip']+' -oN ./'+carpeta+'/'+target_folder_name+'/escaneo-udp' , shell=True)

		if 'c' in procesos:
			print('\n____________________________\n\nESCANEO TCP DE: '+item_of_targets['Nombre']+'\n____________________________')
			subprocess.call('sudo nmap -sS --top-ports 10000 -v '+item_of_targets['Ip']+' -oN ./'+carpeta+'/'+target_folder_name+'/escaneo-tcp'  , shell=True)

		if 'd' in procesos:
			print('\n____________________________\n\nSISTEMA OPERATIVO Y SERVICIOS EN PUERTOS DE: '+item_of_targets['Nombre']+'\n____________________________')
			subprocess.call('sudo nmap -sV -O -v '+item_of_targets['Ip']+' -oN ./'+carpeta+'/'+target_folder_name+'/so_y_puertos', shell=True)

		if 'e' in procesos:
			print('\n____________________________\n\nBUSQUEDA DE VULNERABILIDADES DE: '+item_of_targets['Nombre']+'\n____________________________')
			subprocess.call('sudo nmap -sV --script vulners --script-args mincvss=5.0 '+item_of_targets['Ip']+' -oN ./'+carpeta+'/'+target_folder_name+'/vulnerabilidades', shell=True)
			direccion='./'+carpeta+'/'+target_folder_name+'/vulnerabilidades'
			graficar(direccion)
		if 'f' in procesos:
			print('\n____________________________\n\nENUMERACION DE NetBios DE: '+item_of_targets['Nombre']+'\n____________________________')
			direccion = './'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt'

			append_to_a_text(direccion,'nmblookup -A '+item_of_targets['Ip'])
			subprocess.call('nmblookup -A '+item_of_targets['Ip']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt',shell=True)

			append_to_a_text(direccion,'nbtscan '+item_of_targets['Ip'])
			subprocess.call('nbtscan '+item_of_targets['Ip']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt',shell=True)
		
			append_to_a_text(direccion,'sudo nmap --script smb-os-discovery '+item_of_targets['Ip'])
			subprocess.call('sudo nmap --script smb-os-discovery '+item_of_targets['Ip']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt',shell=True)

			append_to_a_text(direccion,'sudo nmap --script nbstat.nse '+item_of_targets['Ip'])
			subprocess.call('sudo nmap --script nbstat.nse '+item_of_targets['Ip']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt',shell=True)

			append_to_a_text(direccion,'smbmap -H '+item_of_targets['Ip'])
			subprocess.call('smbmap -H '+item_of_targets['Ip']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/NetBios-enum.txt',shell=True)
		if 'g' in procesos:
			print('\n____________________________\n\nENUMERACION DNS DE: '+item_of_targets['Nombre']+'\n____________________________')
			subprocess.call('dnsenum --enum --noreverse -o ./'+carpeta+'/'+target_folder_name+'/DNS-enum '+item_of_targets['Nombre']+' | tee -a ./'+carpeta+'/'+target_folder_name+'/DNS-enum.txt', shell=True)



"""
if len(sys.argv) == 3:

	ip=sys.argv[1]
	nombre=sys.argv[2]

	subprocess.call('nmap -sn -n '+ip+'/24 -oG enumeracion-'+nombre+'.ip', shell=True)
	subprocess.call('cat enumeracion-'+nombre+'.ip | cut -d " " -f2 > ips-'+nombre+'.txt', shell=True)
	subprocess.call('wc -l ips-'+nombre+'.txt', shell=True)


	ips = open('ips-'+nombre+'.txt','r')
	lineas = ips.readlines()
	ips.close()

	ips = open('ips-'+nombre+'.txt','w')
	for linea in lineas:
		if(linea != "Nmap"+"\n"):
			ips.write(linea)
	ips.close()

	subprocess.call('sudo nmap -sU -p1-200 -n -v -iL ips-'+nombre+'.txt ', shell=True)
	subprocess.call('sudo nmap -sS -p1-200 -n -v -iL ips-'+nombre+'.txt ', shell=True)
	subprocess.call('sudo nmap -sV -O -n -v -iL ips-'+nombre+'.txt -oG report-'+nombre, shell=True)

else:

	print("\nERROR - Argumentos insuficientes - recuerde que la estructura es: python automat.py [ip] [sufijo-archivo]")
	print("\n[ip] -> ip del objetivo, debe terminar en 0 para evaluar a todo el conjunto de direcciones")
	print("[sufijo-archivo] -> nombre que se le pone al final a los diferentes archivos genrados ej: enumeracion-[sufijo-archivo]")
	print("\nEjemplo: python automat.py 188.8.5.0 prueba")

"""
