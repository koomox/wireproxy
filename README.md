# wireproxy

## Install        
```sh
sudo chmod +x ./wireproxy
sudo cp -f ./wireproxy /usr/bin/wireproxy
```
systemd service            
```sh
sudo cp -f ./wireproxy.service /etc/systemd/system/wireproxy.service
sudo systemctl enable wireproxy

sudo systemctl start wireproxy
sudo systemctl status wireproxy
```
configure file           
```
[Interface]
PrivateKey = xxxxxxxxxxxxxxxxxx
Address = 172.16.0.2/32, 2606:4700:110:8d44:a7a8:52e5:a5e:c043/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408

[Socks5]
BindAddress = 127.0.0.1:1080
```
Endpoint IPv4 range:         
```
162.159.193.1 - 162.159.193.10
162.159.192.0 - 162.159.192.254
162.159.195.0 - 162.159.195.254
```
Endpoint Port range: 2408, 1701, 500, 4500, 908         