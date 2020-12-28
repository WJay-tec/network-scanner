
from scapy.layers.inet import *  # import * meaning import everything
from scapy.sendrecv import *
from ipaddress import *

# Ping Sweep
hostUp = []
checkPort = []
checkPort2 = []
ipused = []
print("enter number 1 for ICMP scan , number 2 for SYN scan , number 3 for decoy scan")
userChoice3 = int(input())
sourceip = input(str("enter source ip"))
userchoice = input(str("enter starting ip range"))
userchoice2 = input(str("enter end of ip range"))
porttest = 1

def decoy():
    i = 0
    while i <= 5:
        randnum = random.randint(1,20)
        ipaddress = IPv4Address(sourceip) + randnum
        i += 1
        ipused.append(ipaddress)
    return ipused

def icmp(userran1,userran2,choice):
    while IPv4Address(userran1) <= IPv4Address(userran2):
        if choice == 3:
            decoy()
            for x in ipused:
                print("IP in used to scan is ="+" "+str(x))
                test = IP(src= x, dst= str(userran1), ttl= 64)/ICMP()
                reply = sr1(test,timeout =1)
            print("IP in used to scan is =" + " " +"192.168.0.135" )
            test2 = IP(src = "192.168.0.135",dst= str(userran1), ttl= 64)/ICMP()
            reply = sr1(test2,timeout =1)

        else:
            test = IP(src = "192.168.0.135", dst = str(userran1), ttl=64) / ICMP()
            reply = sr1(test, timeout=1,)         # the 1 beside the sr means that it will end after getting 1 respond
                                      #we can see that it received alot of packets, those are non-response packets while waiting for the response
        if reply != None:
            hostUp.append(userran1)
        print(userran1)
        userran1 = IPv4Address(userran1)+1
    return hostUp


def syn(port,userran1,userran2,choice): # normal SYN scan
    icmp(userran1,userran2,choice)
    decoy()
    for x in hostUp:
        print("Alive host are" + " " + str(x))
        while port != 50000:
            randport = random.randint(1024,65535)
            if choice == 3:
                for y in ipused:
                    print("IP used to scan port "+str(port)+"is = " +" "+str(y))
                    tcpscan = IP(src=y, dst = str(x) , ttl = 4)/TCP(sport = randport,dport=port, flags="S")/"test123"
                    reply2 = sr1(tcpscan, timeout=1)
                print("IP used to scan port "+str(port)+"is = " +" "+"192.168.0.135")
                tcpscan2 = IP(src="192.168.0.135", dst=str(x), ttl=4) / TCP(sport=randport, dport=port, flags="S") / "test123"
                reply2 = sr1(tcpscan2, timeout=1)
            else:
                print("IP used to scan port is="+" "+"192.168.0.135")
                tcpscan = IP(src="192.168.0.135", dst = str(x) , ttl = 4)/TCP(sport = randport,dport=port, flags="S")/"test123"
                reply2 = sr1(tcpscan , timeout= 1)
            if reply2 == None:
                reply3 = sr1(tcpscan, timeout=1)
                if reply3 == None:
                    checkPort2.append(str(port)+" "+"is closed, tested through retransmission")
            elif reply2 != None:
                check = reply2.summary()
                check2 = check.find("RA")
                if check2 != -1:
                    checkPort2.append(str(port)+" "+"this port is closed")
                else:
                    checkPort.append(str(port)+" "+str(x)+" "+check)
                    send(IP(src="192.168.0.135", dst=str(x), ttl=4)/TCP(sport=randport, dport=port, flags="R"))

            print(port)
            port += 1
    for y in checkPort:
        print("These are the up and running ports"+" "+y)


if userChoice3 == 1:
    icmp(userchoice, userchoice2,userChoice3)
elif userChoice3 == 2:
    syn(porttest, userchoice, userchoice2,userChoice3)
else:
    print("1 for decoy ICMP scan, 2 for decoy port scan")
    decoyinput = int(input())
    if decoyinput == 1:
        icmp(userchoice,userchoice2,userChoice3)
    else:
        syn(porttest,userchoice,userchoice2,userChoice3)

# parameter name in the function cannot be the same as the global variable
# reply2.summary receives RA / Padding , RA means RST ACK, it basically acknowledges the tcp syn , but since port is closed, a rst is sent


