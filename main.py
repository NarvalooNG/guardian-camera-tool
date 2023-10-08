from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.clock import Clock
from pywifi import const
from pythonping import ping
import re
import socket
import http.client
import requests
import json
import time
import netifaces
import base64
import subprocess
import pywifi
import concurrent.futures

def disconnect_from_network(iface):
    iface.disconnect()
    time.sleep(1)

def connect_to_network(iface, ssid, password):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    iface.remove_all_network_profiles()
    tmp_profile = iface.add_network_profile(profile)
    iface.connect(tmp_profile)

    time.sleep(1)
try:
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
except: 
    pass

senhas_dict = {
    "wifi": {
        "passwords": [
            "30614734",
            "admin", 
            "michelangelo",
            "password",
            "",
            "ltecl4r0",
            "msfadmin",
            "31012003",
            "123456",
            "maravilha10"
        ]
    },
    "roteador": {
        "user": [
            "admin",
            "sitecom",
            "",
            "1admin0",
            "msfadmin"
        ],
        "password": [
            "admin", 
            "michelangelo",
            "password",
            "",
            "ltecl4r0",
            "msfadmin"
        ]
    },
    "camera": {
        "usuario": [
            "admin",
            "12345", 
            "root",
            "123456",
            "9999",
            "pass",
            "service",
            "camera",
            "1111",
            "ce",
            "666666",
            "888888",
            "1234",
            "11111111",
            "HuaWei123",
            "ChangeMe123",
            "config",
            "instar",
            "123456789",
            "Admin",
            "system",
            "jvc",
            "ms1234",
            "meinsm",
            "password",
            "4321",
            "1111111",
            "99999999",
            "ikwd",
            "ubnt",
            "supervisor",
            "wbox1234",
            "123",
            ""
        ],
        "password": [
            "admin",
            "12345", 
            "root",
            "123456",
            "9999",
            "pass",
            "service",
            "camera",
            "1111",
            "ce",
            "666666",
            "888888",
            "1234",
            "11111111",
            "HuaWei123",
            "ChangeMe123",
            "config",
            "instar",
            "123456789",
            "Admin",
            "system",
            "jvc",
            "ms1234",
            "meinsm",
            "password",
            "4321",
            "1111111",
            "99999999",
            "ikwd",
            "ubnt",
            "supervisor",
            "wbox1234",
            "123",
            ""
        ]
    }
}

def ping_ip(ip):
    try:
        result = ping(ip, verbose=False, timeout=1, count=1, size=1)
        return result
    except Exception as e:
        return None

class SimpleApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical', spacing=10)

        self.scan_button = Button(
            text='SCAN na rede',
            size_hint=(None, None),
            size=(300, 150),
            pos_hint={'center_x': 0.5}
        )
        self.scan_button.bind(on_press=self.on_scan_button_click)
        self.layout.add_widget(self.scan_button)

        self.connect_button = Button(
            text='Testar senha do Wifi',
            size_hint=(None, None),
            size=(300, 150),
            pos_hint={'center_x': 0.5}
        )
        self.connect_button.bind(on_press=self.on_connect_button_click)
        self.layout.add_widget(self.connect_button)

        self.story_label = Label(
            text='',
            font_size=24,
            halign='center',
            valign='middle'
        )
        self.layout.add_widget(self.story_label)

        return self.layout

    def on_scan_button_click(self, instance):
        self.story_label.text = "Aguarde, esse processo irá demorar um tempo..."
        self.scan_button.disabled = True
        self.connect_button.disabled = False
        Clock.schedule_once(self.update_ip, 0.1)

    def on_connect_button_click(self, instance):
        self.story_label.text = "Aguarde, esse processo irá demorar um tempo..."
        self.scan_button.disabled = False
        self.connect_button.disabled = True
        Clock.schedule_once(self.wifi_connect, 0.1)

    def wifi_connect(self, dt):
        try:
            connected_network = iface.status()

            if connected_network == const.IFACE_CONNECTED:
                connected_cell = iface.network_profiles()[0]
                connected_ssid = connected_cell.ssid
                disconnect_from_network(iface)
                
                indice = False
                
                for z in range(0, len(senhas_dict['wifi']['passwords'])):
                    senha = senhas_dict['wifi']['passwords'][z]
                    connect_to_network(iface, connected_ssid, senha)
                    time.sleep(1)
                    new_connected_network = iface.status()

                    if new_connected_network == const.IFACE_CONNECTED:
                        self.story_label.text = f"ALERTA! Acesso ao Wifi inseguro. Senha fraca ou inexistente."
                        self.connect_button.disabled = False
                        indice = True
                        break
                
                if indice == False:
                    self.story_label.text = "Aparentemente sua senha do Wifi está segura."
                    self.connect_button.disabled = False
            else:
                self.story_label.text = "Falha na verificação. Verifique se você está conectado à uma rede wifi."
                self.connect_button.disabled = False
        except:
            self.story_label.text = "Ocorreu um erro, verifique se você possui uma interface de rede."
            self.connect_button.disabled = False

    def update_ip(self, dt):       
        openPortsPUB = []
        openPortsPRIV = []
        ip = get_public_ip()
        gw = netifaces.gateways()
        ip_router = gw['default'][netifaces.AF_INET][0]

        ports = [21, 22, 23, 80, 443]

        def check_open_ports(ip_address, port_list):
            open_ports = []
            for port in port_list:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                return_code = sock.connect_ex((ip_address, port))
                sock.close()
                if return_code == 0:
                    open_ports.append(port)
            return open_ports

        openPortsPUB = check_open_ports(ip, ports)
        openPortsPRIV = check_open_ports(ip_router, ports)
                    
        port_descriptions = {
            21: "A porta 21 é usada para comunicações de transferência de arquivos através do protocolo FTP\n" 
                "(File Transfer Protocol). Deixá-la aberta pode expor seus arquivos e seu disposivo\n" 
		        "a riscos de segurança.\n",
            22: "A porta 22 é usada para acesso seguro via SSH (Secure Shell). Deixá-la aberta pode permitir\n"
                "acesso não autorizado ao seu sistema.\n",
            23: "A porta 23 é usada para conexões de terminal remoto com o protocolo Telnet, que é inseguro, \n"
            	"pois as informações são transmitidas em texto simples. Deixar esta porta aberta pode expor \n"
            	"informações confidenciais.\n",
            80: "A porta 80 é a porta padrão para tráfego HTTP, usado para acessar sites da web. Deixar essa \n"
                "porta aberta pode expor seu servidor web a ataques.\n",
            443: "A porta 443 é usada para tráfego HTTPS, que é uma versão segura do HTTP. É usada para transações \n"
                 "seguras na web, como login e pagamento. Deixar essa porta aberta é geralmente seguro, desde que \n"
                 "configurada corretamente com certificados SSL/TLS."
        }
    
        camera = ""
        iscamera = False
        
        octets = ip_router.split(".")[:3]
        ip_default = ".".join(octets)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            ips_to_ping = [ip_default + "." + str(i) for i in range(256)]
            list(executor.map(ping_ip, ips_to_ping))

        arp_command = ['arp', '-a']
        output = subprocess.check_output(arp_command, stderr=subprocess.STDOUT).decode('latin1')
        
        if("00-40-8c" in output):
            axis = True
            iscamera = True
            mac_address_to_find = "00-40-8c"
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+' + re.escape(mac_address_to_find)
            ip_match = re.search(ip_pattern, output)
            
            if ip_match:
                ip_address = ip_match.group(1)
            
            LOGINURL = f"http://{ip_address}/view/viewer_index.shtml"
            USERNAME = "root"

            passwords = senhas_dict['camera']['password']
            
            for PASSWORD in passwords:
                auth_header = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

                headers = {
                    "Authorization": auth_header
                }

                response = requests.get(LOGINURL, headers=headers)

                if response.status_code == 200:
                    axis = False
                    camera = camera + f"\nALERTA! Sua senha da página de sua câmera AXIS está insegura!"
                    break
            
            if(axis):
                camera = camera + f"\nAparentemente sua senha da câmera AXIS está segura. Note que o usuário root é padrão."
        
        if("00-0d-88" in output):
            iscamera = True
            mac_address_to_find = "00-0d-88"
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+' + re.escape(mac_address_to_find)
            ip_match = re.search(ip_pattern, output)
            
            if ip_match:
                ip_address = ip_match.group(1)
            
            LOGINURL = f"http://{ip_address}"
            response = requests.get(LOGINURL)

            if(response.status_code == 200):
                camera = camera + f"\nALERTA! Câmera D-Link sem usuário e sem senha, extremamente vulnerável."
            elif(response.status_code == 401):
                users = senhas_dict['camera']['password']
                passwords = senhas_dict['camera']['password']
                dlink = True

                for USERNAME in users:
                    if(not dlink):
                        break

                    for PASSWORD in passwords:
                        auth_header = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

                        headers = {
                            "Authorization": auth_header
                        }

                        response = requests.get(LOGINURL, headers=headers)

                        if response.status_code == 200:
                            camera = camera + f"\nALERTA! Seu usuário e senha da página de sua câmera D-Link estão inseguros!"
                            dlink = False
                            break
                
                if(dlink):
                    camera = camera + f"\nAparentemente, seu usuário e senha da câmera D-Link está segura."
        
        if(not iscamera):
            camera = f"\nNenhuma câmera detectada."

        for i in range(0, len(senhas_dict['roteador']['user'])):
            for y in range(0, len(senhas_dict['roteador']['password'])):
                usuario = senhas_dict['roteador']['user'][i]
                senha = senhas_dict['roteador']['password'][y]
                success, status_code = testar_login(usuario, senha)

                if success and status_code == 200:
                    text = f"ALERTA! Seu usuário e senha da página do roteador estão inseguros.{camera}"
                    if not openPortsPUB:
                        text += "\nNão há nenhuma porta aberta em seu IP público."
                    else:
                        text += f"\nPortas abertas no IP público: {openPortsPUB}"

                    if not openPortsPRIV:
                        text += "\nNão há nenhuma porta aberta em seu roteador."
                    else:
                        text += f"\nPortas abertas no roteador: {openPortsPRIV}"

                    common_ports = []

                    for elemento in openPortsPUB:
                        if elemento not in common_ports:
                            common_ports.append(elemento)

                    for elemento in openPortsPRIV:
                        if elemento not in common_ports:
                            common_ports.append(elemento)

                    if common_ports:
                        for port in common_ports:
                            if port in port_descriptions:
                                text += f"\n{port_descriptions[port]}"
                    
                    text += "\nSaiba mais em www.speedguide.net/ports_sg.php"
                    
                    self.story_label.text = f"{text}"
                    self.scan_button.disabled = False
                    return
                
                elif not success and status_code == 3301:
                    self.story_label.text = "Roteador não cadastrado."
                    self.scan_button.disabled = False
                    return
        
        text = f"Aparentemente, seu usuário e senha da página do roteador estão seguros."

        if not openPortsPUB:
            text += "\nNão há nenhuma porta aberta em seu IP público."
        else:
            text += f"\nPortas abertas no IP público: {openPortsPUB}"

        if not openPortsPRIV:
            text += "\nNão há nenhuma porta aberta em seu roteador."
        else:
            text += f"\nPortas abertas no roteador: {openPortsPRIV}"

        common_ports = []

        for elemento in openPortsPUB:
            if elemento not in common_ports:
                common_ports.append(elemento)

        for elemento in openPortsPRIV:
            if elemento not in common_ports:
                common_ports.append(elemento)

        if common_ports:
            for port in common_ports:
                if port in port_descriptions:
                    text += f"\n{port_descriptions[port]}"
        
        text += "\nSaiba mais em www.speedguide.net/ports_sg.php"
                    
        self.story_label.text = f"{text}"
        self.scan_button.disabled = False
        return

def testar_login(usuario, senha):
    gw = netifaces.gateways()
    ip_router = gw['default'][netifaces.AF_INET][0]
            
    arp_command = ['arp', '-a', ip_router]
    output = subprocess.check_output(arp_command, stderr=subprocess.STDOUT).decode('latin1')
    
    if("c4-6e-1f" in output):
        LOGINURL = "http://" + ip_router
        
        auth_header = "Basic " + base64.b64encode(f"{usuario}:{senha}".encode()).decode()
        
        headers = {
            "Authorization": auth_header
        }
        
        response = requests.get(LOGINURL, headers=headers)
    
    elif("d8-d7-75" in output):
        LOGINURL = "http://" + ip_router + f"/timlogin.cgi?loginuser={usuario}&loginpasswd={senha}"

        response = requests.get(LOGINURL)
    
    else:
        return False, 3301

    if response.status_code == 200:
        return True, 200
    else:
        return False, 401

def get_public_ip():
    response = http.client.HTTPSConnection("api.ipify.org")
    response.request("GET", "/?format=json")
    ip_data = json.loads(response.getresponse().read())

    return ip_data['ip']

if __name__ == '__main__':
    SimpleApp().run()