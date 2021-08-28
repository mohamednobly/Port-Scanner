# Port-Scanner
- Python port scanner 
- Works on both Linux and Windows 
- Supports UDP and TCP 
- Supports Nmap Service Enumeration 
# Install 
git clone https://github.com/mohamednobly/Port-Scanner.git


cd Port-Scanner && pip3 install -r requirements.txt
# Usage 
python3 Port-Scanner.py --help 



____   _                    _         ____                _     ____                                         
/ ___| (_) _ __ ___   _ __  | |  ___  |  _ \   ___   _ __ | |_  / ___|   ___   __ _  _ __   _ __    ___  _ __ 
\___ \ | || '_ ` _ \ | '_ \ | | / _ \ | |_) | / _ \ | '__|| __| \___ \  / __| / _` || '_ \ | '_ \  / _ \| '__|
 ___) || || | | | | || |_) || ||  __/ |  __/ | (_) || |   | |_   ___) || (__ | (_| || | | || | | ||  __/| |   
|____/ |_||_| |_| |_|| .__/ |_| \___| |_|     \___/ |_|    \__| |____/  \___| \__,_||_| |_||_| |_| \___||_|   
                     |_|                                                                                      

                                                by n0bly
[+] Started at DATE
usage: Port-Scanner.py [-h] [--target TARGET] [--tcp] [--udp] [--TopPorts] [--AllPorts] [--verbose]

optional arguments:
  -h, --help       show this help message and exit
  --target TARGET  Use Target Ip, Range, Subnet or Hostname
  --tcp            TCP Scan
  --udp            UDP Scan
  --TopPorts       Scan Top Ports
  --AllPorts       Full Port Scan
  --verbose        Verobse

 
        ./file.py --help -----> Display the Full Help Menu 

        ./file.py --target 'Target' -----> TCP Port Scan and NMAP Service Scan 

        ./file.py --target 'Target' --udp -----> UDP Port Scan and NMAP Service Scan 

        ./file.py --target 'Target' --udp --tcp -----> TCP and UDP Port Scan and NMAP Service Scan 


                                                                                        
