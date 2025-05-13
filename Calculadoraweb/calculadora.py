from flask import Flask, render_template, request
import ipaddress

app = Flask(__name__)

def ip_a_binario(ip_str):
    octetos = list(map(int, ip_str.split('.')))
    return ''.join(f"{octeto:08b}" for octeto in octetos)

def binario_a_ip(binario):
    return '.'.join(str(int(binario[i:i+8], 2)) for i in range(0, 32, 8))

def calcular_red_broadcast_manual(ip_str, mask_str):

    ip_bin = ip_a_binario(ip_str)
    mask_bin = ip_a_binario(mask_str)
    
    prefijo = mask_bin.count('1')
    
    red_bin = ''.join(str(int(ip_bit) & int(mask_bit)) for ip_bit, mask_bit in zip(ip_bin, mask_bin))
    
    broadcast_bin = red_bin[:prefijo] + '1' * (32 - prefijo)
    
    return binario_a_ip(red_bin), binario_a_ip(broadcast_bin)

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

def a_binario(ip, network):
    return ' '.join(f"{octet:08b}" for octet in ip.packed)


def validar_ip_masc(ip_str, mask_str):
    try:
        
        network = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        ip = ipaddress.IPv4Address(ip_str)
        
        if ip not in network:
            raise ValueError(f"La IP {ip_str} no pertenece a la red {network}")
            
       
        ip_red_str, broadcast_str = calcular_red_broadcast_manual(ip_str, mask_str)
        ip_red = ipaddress.IPv4Address(ip_red_str)
        broadcast = ipaddress.IPv4Address(broadcast_str)
        
        return network, ip, ip_red, broadcast
        
    except ipaddress.AddressValueError:
        raise ValueError("Formato de IP inválido")
    except ipaddress.NetmaskValueError:
        raise ValueError("Máscara inválida")


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            ip_str = request.form['ip']
            mask_str = request.form['mask']
            
           
            network, ip, ip_red, broadcast = validar_ip_masc(ip_str, mask_str)
            
            
            hosts = max(network.num_addresses - 2, 0)
            rango_util = f"{ip_red + 1}-{broadcast - 1}" if network.prefixlen <= 30 else "N/A"
            clase = clase_ip(ip_red)
            tipo = 'Privada' if es_privada(ip_red) else 'Pública'
            binario = a_binario(ip, network)
            
            return render_template('index.html',
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
    app.run(host='0.0.0.0', port=80)
