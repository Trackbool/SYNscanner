# SYNscanner
![alt text](https://i.gyazo.com/d4dc96b38f2f12ebfd70201cde9f4dc6.png)

Simple port scanning tool made in Python 3 with Scapy. Uses the TCP SYN probe to discover open, closed and filtered ports

## Usage

* Download it from git or use **_'git clone https://github.com/Trackbool/SYNscanner'_**
* You need the Scapy Python module. You can install the requirements with: **_'pip3 install -r requirements.txt'_** (recomended) or manually **_'pip3 install scapy'_**
* Scapy uses tcpdump
* To execute the tool, you will need root permissions

Help menu:

	[!] Options to use:
	<ip>  - Scan the ports of victim's IP address
	-p    - Specify the port or ports range | -p 1-100
	-c    - Show the closed ports
	-h    - This help menu

#### If you have any question: 
Adrián Fernández Arnal (@adrianfa5)
Twitter: https://twitter.com/adrianfa5
