# Port-Scanner
- Python port scanner 
- Works on both Linux and Windows 
- Supports UDP and TCP 
- Supports Nmap Service Enumeration 
# Install 

```bash
git clone https://github.com/mohamednobly/Port-Scanner.git
```
```bash
cd Port-Scanner && pip3 install -r requirements.txt

```
# Usage 
python3 Port-Scanner.py --help 



           
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


                                                                                        
