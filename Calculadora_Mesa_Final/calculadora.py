from flask import Flask, render_template, request
import ipaddress

app = Flask(__name__)

def ip_a_binario(ip_str):
    octetos = list(map(int, ip_str.split('.')))
    return '.'.join(f"{octeto:08b}" for octeto in octetos)

def binario_a_ip(binario):
    binario = binario.replace('.', '')
    return '.'.join(str(int(binario[i:i+8], 2)) for i in range(0, 32, 8))

def calcular_red_broadcast_manual(ip_str, mask_str):
    network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
    
    red_str = str(network.network_address)
    broadcast_str = str(network.broadcast_address)
    
    return red_str, broadcast_str

def es_privada(ip):
    return ip.is_private

def clase_ip(ip):
    octeto = int(ip.packed[0])
    if 1 <= octeto <= 126:
        return 'A'
    elif 128 <= octeto <= 191:
        return 'B'
    elif 192 <= octeto <= 223:
        return 'C'
    elif 224 <= octeto <= 239:
        return 'D'
    else:
        return 'E'

def formato_binario(ip):
    return ip_a_binario(str(ip))

def validar_ip_masc(ip_str, mask_str):
    try:
        if mask_str.startswith('/'):
            prefix_len = int(mask_str[1:])
            if prefix_len < 0 or prefix_len > 32:
                raise ValueError("El prefijo debe estar entre 0 y 32")
            network = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
            mask_str = str(network.netmask)  
        elif mask_str.isdigit():
            prefix_len = int(mask_str)
            if prefix_len < 0 or prefix_len > 32:
                raise ValueError("El prefijo debe estar entre 0 y 32")
            network = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
            mask_str = str(network.netmask)  
        else:
            ipaddress.IPv4Address(mask_str) 
            network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        
        ip = ipaddress.IPv4Address(ip_str)
        
        if ip not in network:
            raise ValueError(f"La IP {ip_str} no pertenece a la red {network}")
        
        ip_red = network.network_address
        broadcast = network.broadcast_address
        
        return network, ip, ip_red, broadcast
        
    except ipaddress.AddressValueError:
        raise ValueError("Formato de IP inválido")
    except ipaddress.NetmaskValueError:
        raise ValueError("Máscara inválida")
    except ValueError as e:
        if "El prefijo debe estar entre 0 y 32" in str(e):
            raise
        raise ValueError("Formato de máscara inválido")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            ip_str = request.form['ip']
            mask_str = request.form['mask']
            
            network, ip, ip_red, broadcast = validar_ip_masc(ip_str, mask_str)
            
            hosts = max(network.num_addresses - 2, 0)
            
            if network.prefixlen < 31:
                first_usable = ip_red + 1
                last_usable = broadcast - 1
                rango_util = f"{first_usable} - {last_usable}"
            elif network.prefixlen == 31:
                rango_util = f"{ip_red} - {broadcast}"
            else:  
                rango_util = f"{ip}"
                
            clase = clase_ip(ip_red)
            tipo = 'Privada' if es_privada(ip) else 'Pública'
            binario = formato_binario(ip)
            
            mask_decimal = str(network.netmask)
            mask_cidr = f"/{network.prefixlen}"
            
            return render_template('index.html',
                ip=ip_str,
                mask_decimal=mask_decimal,
                mask_cidr=mask_cidr,
                ip_red=ip_red,
                broadcast=broadcast,
                hosts=hosts,
                rango=rango_util,
                clase=clase,
                tipo=tipo,
                binario=binario,
                show_results=True)
            
        except ValueError as e:
            error = f"Error: {str(e)}"
            return render_template('index.html', error=error, show_results=False)
    
    return render_template('index.html', show_results=False)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)