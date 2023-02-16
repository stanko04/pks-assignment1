import sys
sys.path.append("c:/users/adam4/appdata/roaming/python/python39/site-packages")
from scapy.all import *
from collections import Counter
from scapy. layers. inet import IP
sys.path.append("c:/python39/lib/site-packages")
import yaml
import ruamel.yaml
import json

#open .pcap file
def openPcapFile(fileName):
    packet = rdpcap("pcap_files/" + fileName)
    packetList = PacketList([p for p in packet])
    return packetList


def write_all_frames(packetList, fileName):
    senders_ip = []
    # Open json file
    f = open('data.json')
    jsonData = json.load(f)

    isl = False

    data = {"name": "PKS2022/23", "pcap_name": fileName, "packets": [], "ipv4_senders": [], "max_send_packets_by": []}

    number = 1
    for packet in packetList:
        p = raw(packet)
        # Split frame
        frame = p.hex()
        frameSplit = frame.split()

        # get frame lenght
        frameLenght = int(len(packet))

        # Get frame medium
        if(frameLenght > 60):
            frameMedium = int(len(packet)) + 4
        else:
            frameMedium = 64

        # destination mac
        dstMac = str(frame[0]) + str(frame[1]) + ':' + str(frame[2]) + str(frame[3]) + ':' + str(frame[4]) + str(frame[5]) + ':' + str(frame[6]) + str(frame[7]) + ':' + str(frame[8]) + str(frame[9]) + ':' + str(frame[10]) + str(frame[11])
        # source mac
        srcMac = str(frame[12]) + str(frame[13]) + ':' + str(frame[14]) + str(frame[15]) + ':' + str(frame[16]) + str(frame[17]) + ':' + str(frame[18]) + str(frame[19]) + ':' + str(frame[20]) + str(frame[21]) + ':' + str(frame[22]) + str(frame[23])

        # ISL
        if(dstMac == '01:00:0c:00:00:00'):
            dstMac = str(frame[52]) + str(frame[53]) + ':' + str(frame[54]) + str(frame[55]) + ':' + str(frame[56]) + str(frame[57]) + ':' + str(frame[58]) + str(frame[59]) + ':' + str(frame[60]) + str(frame[61]) + ':' + str(frame[62]) + str(frame[63])
            srcMac = str(frame[64]) + str(frame[65]) + ':' + str(frame[66]) + str(frame[67]) + ':' + str(frame[68]) + str(frame[69]) + ':' + str(frame[70]) + str(frame[71]) + ':' + str(frame[72]) + str(frame[73]) + ':' + str(frame[74]) + str(frame[75])
            isl = True


        # 13. and 14. byte into decimal for type of Ethernet
        x = frame[24] + frame[25] + frame[26] + frame[27]
        dec = int(x, 16)

        # 15. and 16. bytes for 'IEEE 802.3 RAW'
        z = frame[28] + frame[29] + frame[30] + frame[31]
        decRaw = int(z, 16)

        # Variable for type of frame
        frameType = ''

        # get 15. byte for SNAP
        llcByte = frame[28] + frame[29]

        frameNumber = number

        # Condition for frame type
        if(dec >= 1536):
            frameType = 'Ethernet II'
        if(decRaw == 65535):
            frameType = 'IEEE 802.3 RAW'
        if(dec < 1536 and llcByte == 'aa'):
            frameType = 'IEEE 802.3 LLC & SNAP'
        if not(dec >= 1536 or decRaw == 65535 or (dec < 1536 and llcByte == 'aa')):
            frameType = 'IEEE 802.3 LLC'

        # Get PID for IEEE 802.3 LLC & SNAP
        dec2 = 0
        pid = ''
        if(frameType == 'IEEE 802.3 LLC & SNAP'):
            if not(dstMac == '01:00:0c:00:00:00'):
                y = frame[40] + frame[41] + frame[42] + frame[43]
                dec2 = int(y, 16)
                if(dec2 == 267):
                    pid = 'PVSTP+'
                elif(dec2 == 32923):
                    pid = 'AppleTalk'
                elif(dec2 == 8196):
                    pid = 'DTP'
                elif(dec2 == 8192):
                    pid = 'CDP'

        if(frameType == 'IEEE 802.3 LLC & SNAP'):
            if(isl == True):
                y2 = frame[92] + frame[93] + frame[94] + frame[95]
                dec3 = int(y2, 16)
                if(dec3 == 267):
                    pid = 'PVSTP+'
                elif(dec3 == 32923):
                    pid = 'AppleTalk'
                elif(dec3 == 8196):
                    pid = 'DTP'
                elif(dec3 == 8192):
                    pid = 'CDP'

        # Get SAP for IEE 802.3 LLC
        dec3 = 0
        sap = ''
        if(frameType == 'IEEE 802.3 LLC'):
            w = frame[30] + frame[31]
            dec3 = int(w, 16)
            if(dec3 == 66): # STP -> 42
                sap = 'STP'
            elif(dec3 == 224): # IPX -> E0
                sap = 'IPX'
            elif(dec3 == 240): # Netbios -> F0
                sap = 'NETBIOS'

        # Ethernet II type
        app_protocol = ''
        if(frameType == 'Ethernet II'):
            eth_type = ''
            val = str(x)
            for key, value in jsonData['eth_type'].items():
                if(key == val):
                    eth_type = value
                    if(eth_type == 'IPv4'):
                        srcIP = str(int((frame[52] + frame[53]), 16)) + "." + str(int((frame[54] + frame[55]), 16)) + "." + str(int((frame[56] + frame[57]), 16)) + "." + str(int((frame[58] + frame[59]), 16))
                        dstIP = str(int((frame[60] + frame[61]), 16)) + "." + str(int((frame[62] + frame[63]), 16)) + "." + str(int((frame[64] + frame[65]), 16)) + "." + str(int((frame[66] + frame[67]), 16))
                        senders_ip.append(srcIP)
                        for key, value in jsonData['protocols'].items():
                            if(key == str(frame[46] + frame[47])):
                                protocol = value
                        if(protocol == 'UDP'):
                            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                            for key, value in jsonData['app_protocol'].items():
                                if(key == str(src_port) or key == str(dst_port)):
                                    app_protocol = value
                        if(protocol == 'TCP'):
                            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                            for key, value in jsonData['app_protocol'].items():
                                if(key == str(src_port) or key == str(dst_port)):
                                    app_protocol = value
                    if(eth_type == 'ARP'):
                        srcIP = str(int((frame[56] + frame[57]), 16)) + "." + str(int((frame[58] + frame[59]), 16)) + "." + str(int((frame[60] + frame[61]), 16)) + "." + str(int((frame[62] + frame[63]), 16))
                        dstIP = str(int((frame[76] + frame[77]), 16)) + "." + str(int((frame[78] + frame[79]), 16)) + "." + str(int((frame[80] + frame[81]), 16)) + "." + str(int((frame[82] + frame[83]), 16))


        # Hexa frame
        hexaFrame = ''
        i = 1;
        for z in frame:
            if not(i%32==0):
                if(i != len(frame)):
                    if(i%2 == 0):
                        hexaFrame += z + " "
                        # print(z, end=" ")
                    else:
                        hexaFrame += z
                        # print(z, end="")
            if(i == len(frame)):
                hexaFrame += z + "\n"
                break
            if(i%32 == 0):
                hexaFrame += z + "\n"
                # print(z,  end="\n")
            i = i+1


        if(frameType == 'Ethernet II'):
            if(eth_type == 'ARP'):
                packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                               'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, "ether_type": eth_type, 'src_ip': srcIP, 'dst_ip': dstIP,
                               'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
            if(eth_type == 'IPv4'):
                if(protocol == 'TCP' or protocol == 'UDP'):
                    if not(app_protocol == ''):
                        packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                                       'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, "ether_type": eth_type, 'src_ip': srcIP, 'dst_ip': dstIP, 'protocol': protocol,
                                       'src_port': src_port, 'dst_port': dst_port, 'app_protocol': app_protocol, 'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
                    else:
                        packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                                       'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, "ether_type": eth_type, 'src_ip': srcIP, 'dst_ip': dstIP, 'protocol': protocol,
                                       'src_port': src_port, 'dst_port': dst_port,'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
                else:
                    packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                                   'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, "ether_type": eth_type, 'src_ip': srcIP, 'dst_ip': dstIP, 'protocol': protocol,
                                   'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
            if not(eth_type == 'IPv4' or eth_type == 'ARP'):
                packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                               'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, "ether_type": eth_type,
                               'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
        if(frameType == 'IEEE 802.3 LLC & SNAP'):
            packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                               'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, 'pid': pid,
                               'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
        if(frameType == 'IEEE 802.3 LLC'):
            packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                           'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac, 'sap': sap,
                           'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
        if not(frameType == 'Ethernet II' or frameType == 'IEEE 802.3 LLC & SNAP' or frameType == 'IEEE 802.3 LLC'):
            packet_data = {'frame_number': frameNumber, 'len_frame_pcap': frameLenght, 'len_frame_medium': frameMedium,
                           'frame_type': frameType, 'src_mac': srcMac, 'dst_mac': dstMac,
                           'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}


        data["packets"].append(packet_data)
        number = number + 1


    for key, value in Counter(senders_ip).items():
        senders_data = {"node": key, "number_of_sent_packets": value}
        data["ipv4_senders"].append(senders_data)

    number_of_packets = Counter(senders_ip)
    best_senders_list = list(filter(lambda t: t[1]>=number_of_packets.most_common()[0][1], number_of_packets.most_common()))
    for key, value in best_senders_list:
        # max_senders_data = {"node": key, "number_of_sent_packet": value}
        # data["max_send_packets_by"].append(max_senders_data)
        data["max_send_packets_by"].append(key)

    yaml = ruamel.yaml.YAML()
    with open('out.yaml', 'w') as f:
        data = yaml.dump(data, f, )

def tcp_protocols(packetList, fileName, protocol):

    http_frames = []
    number_http_frames = []

    # Open json file
    f = open('data.json')
    jsonData = json.load(f)
    for key, value in jsonData['app_protocol'].items():
        if(value == protocol):
            protocol_port = key
            protocol_name = value
            print(value)

    number = 1
    for packet in packetList:
        p = raw(packet)
        # Split frame
        frame = p.hex()
        frameSplit = frame.split()

        # 13. and 14. byte into decimal for type of Ethernet
        x = frame[24] + frame[25] + frame[26] + frame[27]
        dec = int(x, 16)

        # 15. and 16. bytes for 'IEEE 802.3 RAW'
        z = frame[28] + frame[29] + frame[30] + frame[31]
        decRaw = int(z, 16)

        # Variable for type of frame
        frameType = ''

        # get 15. byte for SNAP
        llcByte = frame[28] + frame[29]

        # Condition for frame type
        if(dec >= 1536):
            frameType = 'Ethernet II'
        if(decRaw == 65535):
            frameType = 'IEEE 802.3 RAW'
        if(dec < 1536 and llcByte == 'aa'):
            frameType = 'IEEE 802.3 LLC & SNAP'
        if not(dec >= 1536 or decRaw == 65535 or (dec < 1536 and llcByte == 'aa')):
            frameType = 'IEEE 802.3 LLC'

        # Ethernet II type
        app_protocol = ''
        if(frameType == 'Ethernet II'):
            eth_type = ''
            val = str(x)
            for key, value in jsonData['eth_type'].items():
                if(key == val):
                    eth_type = value
                    if(eth_type == 'IPv4'):
                        srcIP = str(int((frame[52] + frame[53]), 16)) + "." + str(int((frame[54] + frame[55]), 16)) + "." + str(int((frame[56] + frame[57]), 16)) + "." + str(int((frame[58] + frame[59]), 16))
                        dstIP = str(int((frame[60] + frame[61]), 16)) + "." + str(int((frame[62] + frame[63]), 16)) + "." + str(int((frame[64] + frame[65]), 16)) + "." + str(int((frame[66] + frame[67]), 16))
                        for key, value in jsonData['protocols'].items():
                            if(key == str(frame[46] + frame[47])):
                                protocol = value
                        if(protocol == 'TCP'):
                            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                            for key, value in jsonData['app_protocol'].items():
                                if(key == protocol_port and (dst_port == int(key) or src_port == int(key))):
                                    # print(str(number) + " + " + str(srcIP) + " + " + str(dstIP))
                                    http_frames.append(packet)
                                    number_http_frames.append(number)
        number = number + 1

    pom = 0

    complete_frames = []
    number_frames = []

    complete_frames = tcp_frames(http_frames, number_http_frames, complete_frames, number_frames, fileName, protocol_name)

def tcp_frames(http_frames, number_http_frames, complete_frames, number_frames, fileName, protocol_name):
    communication = []
    frame_numbers = []
    if (len(http_frames) > 0):
        b = raw(http_frames[0])
        frame = b.hex()
        frameSplit = frame.split()

        main_src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
        main_dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)

        new_arr = []
        pom = 0
        for packet in http_frames:
            # print(len(http_frames))
            p = raw(packet)
            # Split frame
            frame = p.hex()
            frameSplit = frame.split()

            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)


            if((src_port == main_dst_port and dst_port == main_src_port) or (src_port == main_src_port and dst_port == main_dst_port)):
                # (src_port == main_dst_port or src_port == main_src_port) and (dst_port == main_src_port or dst_port == main_dst_port)
                # src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]
                communication.append(packet)
                # frame_numbers.append(number_http_frames[pom])
                number_frames.append(number_http_frames[pom])
                # http_frames.remove(packet)
            pom = pom + 1


        new_arr = []
        numbers_arr = []
        pom = 0
        for packet in http_frames:
            # print(len(http_frames))
            p = raw(packet)
            # Split frame
            frame = p.hex()
            frameSplit = frame.split()

            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)


            if not((src_port == main_dst_port or src_port == main_src_port) and (dst_port == main_src_port or dst_port == main_dst_port)):
                # (src_port == main_dst_port or src_port == main_src_port) and (dst_port == main_src_port or dst_port == main_dst_port)
                # src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]
                # communication.append(packet)
                # http_frames.remove(packet)
                new_arr.append(packet)
                numbers_arr.append(number_http_frames[pom])
            pom = pom + 1

        complete_frames.append(communication)
        # number_frames.append(frame_numbers)

        tcp_frames(new_arr, numbers_arr, complete_frames, number_frames, fileName, protocol_name)

    else:
        data = {"name": "PKS2022/23", "pcap_name": fileName, "filter_name": protocol_name, "complete_comms": [], "partial_comms": [] }
        pom = 0
        comm_number = 1
        for packet in complete_frames:
            frames = []
            fin_ack = 0
            rst = 0
            rst_ack = 0
            flags = []
            pom2 = 0
            src_dst = 0
            for p in packet:
                b = raw(p)
                frame = b.hex()
                frameSplit = frame.split()

                flag = frame[94] + frame[95]
                flags.append(flag)

                if(flag == '11' or flag == '19'):
                    fin_ack = fin_ack + 1
                if(flag == '04'):
                    rst = rst + 1
                if(flag == '14'):
                    rst_ack = rst_ack + 1

                main_src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                main_dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                # print(str(number_frames[pom]) + ": " + flags[pom2])

                # destination mac
                dst_mac = str(frame[0]) + str(frame[1]) + ':' + str(frame[2]) + str(frame[3]) + ':' + str(frame[4]) + str(frame[5]) + ':' + str(frame[6]) + str(frame[7]) + ':' + str(frame[8]) + str(frame[9]) + ':' + str(frame[10]) + str(frame[11])
                # source mac
                src_mac = str(frame[12]) + str(frame[13]) + ':' + str(frame[14]) + str(frame[15]) + ':' + str(frame[16]) + str(frame[17]) + ':' + str(frame[18]) + str(frame[19]) + ':' + str(frame[20]) + str(frame[21]) + ':' + str(frame[22]) + str(frame[23])

                # get frame lenght
                frameLenght = int(len(p))

                # Get frame medium
                if(frameLenght > 60):
                    frameMedium = int(len(p)) + 4
                else:
                    frameMedium = 64

                # Hexa frame
                hexaFrame = ''
                i = 1;
                for z in frame:
                    if not(i%32==0):
                        if(i != len(frame)):
                            if(i%2 == 0):
                                hexaFrame += z + " "
                                # print(z, end=" ")
                            else:
                                hexaFrame += z
                                # print(z, end="")
                    if(i == len(frame)):
                        hexaFrame += z + "\n"
                        break
                    if(i%32 == 0):
                        hexaFrame += z + "\n"
                        # print(z,  end="\n")
                    i = i+1

                srcIP = str(int((frame[52] + frame[53]), 16)) + "." + str(int((frame[54] + frame[55]), 16)) + "." + str(int((frame[56] + frame[57]), 16)) + "." + str(int((frame[58] + frame[59]), 16))
                dstIP = str(int((frame[60] + frame[61]), 16)) + "." + str(int((frame[62] + frame[63]), 16)) + "." + str(int((frame[64] + frame[65]), 16)) + "." + str(int((frame[66] + frame[67]), 16))

                if(src_dst == 0):
                    src_comm = srcIP
                    dst_comm = dstIP
                    src_dst = 1

                packet_data = {"frame_number": number_frames[pom], "len_frame_pcap": frameLenght, "len_frame_medium": frameMedium,
                               "frame_type": "Ethernet II", "src_mac": src_mac, "dst_mac": dst_mac, "ether_type": "IPv4", "src_ip": srcIP,
                               "dst_ip": dstIP, "protocol": "TCP", "src_port": main_src_port, "dst_port": main_dst_port,
                               "app_protocol": protocol_name, "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
                frames.append(packet_data)

                pom = pom + 1
                pom2 = pom2 + 1

            # pom = 0
            # comm_number = 0
            # for p in packet:
            #     b = raw(p)
            #     frame = b.hex()
            #     frameSplit = frame.split()
            #
            #     frame_number = number_frames[pom]
            #     pom = pom + 1
            #
            #     destination mac
                # dst_mac = str(frame[0]) + str(frame[1]) + ':' + str(frame[2]) + str(frame[3]) + ':' + str(frame[4]) + str(frame[5]) + ':' + str(frame[6]) + str(frame[7]) + ':' + str(frame[8]) + str(frame[9]) + ':' + str(frame[10]) + str(frame[11])
                # source mac
                # src_mac = str(frame[12]) + str(frame[13]) + ':' + str(frame[14]) + str(frame[15]) + ':' + str(frame[16]) + str(frame[17]) + ':' + str(frame[18]) + str(frame[19]) + ':' + str(frame[20]) + str(frame[21]) + ':' + str(frame[22]) + str(frame[23])
                #
                # packet_data = {"frame_number": frame_number, "src_mac": src_mac, "dst_mac": dst_mac}
                # frames.append(packet_data)


            if(len(flags) > 3):
                if((flags[0] == '02' and flags[1] == '12' and flags[2] == '10') and (fin_ack == 2 or rst == 1 or rst_ack == 1)):
                    comm = {"number_comm": comm_number, "src_comm": src_comm, "dst_comm":dst_comm, "packets": frames}
                    comm_number = comm_number + 1
                    data["complete_comms"].append(comm)
                    print("Complete communication")
                else:
                    comm = {"number_comm": comm_number, "packets": frames}
                    comm_number = comm_number + 1
                    data["partial_comms"].append(comm)
                    print("Incomplete communication")
            else:
                comm = {"number_comm": comm_number, "packets": frames}
                comm_number = comm_number + 1
                data["partial_comms"].append(comm)
                print("Incomplete communication")

            print("---------")

        yaml = ruamel.yaml.YAML()
        with open('out.yaml', 'w') as f:
            data = yaml.dump(data, f)

        with open('out.yaml', 'r') as fr:
            lines = fr.readlines()
            with open('out.yaml', 'w') as fw:
                for line in lines:
                    if (line.strip('\n') != 'complete_comms: []'):
                        fw.write(line)
        with open('out.yaml', 'r') as fr:
            lines = fr.readlines()
            with open('out.yaml', 'w') as fw:
                for line in lines:
                    if (line.strip('\n') != 'partial_comms: []'):
                        fw.write(line)


        return complete_frames

def udp_protocols(packet_list, file_name, protocol):
    # Open json file
    f = open('data.json')
    jsonData = json.load(f)
    for key, value in jsonData['app_protocol'].items():
        if(value == protocol):
            protocol_port = key
            protocol_name = value
            print(value)

    frame_number = 1

    arr_number = []
    number_tftp_frame = 0
    pom = 1
    for p in packet_list:
        b = raw(p)
        # Split frame
        frame = b.hex()
        frameSplit = frame.split()

        src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
        dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)

        if(str(src_port) == protocol_port or str(dst_port) == protocol_port):
            number_tftp_frame = number_tftp_frame + 1
        arr_number.append(pom)
        pom = pom + 1


    print(number_tftp_frame)
    tftp_frames = []
    tftp_numbers = []
    comms = []
    udp_frames(packet_list, file_name, protocol_port, protocol_name, frame_number, tftp_frames, number_tftp_frame, arr_number, tftp_numbers, comms)

def udp_frames(packet_list, file_name, protocol_port, protocol_name, frame_number, tftp_frames, number_tftp_frame, arr_number, tftp_numbers, comms):
    actual_frames = []
    if(number_tftp_frame > 0):
        start_frame = 0
        main_port = 0
        new_arr = []
        new_arr_numbers = []
        frame_numbers = []
        pom = 0
        pom2 = 0
        for p in packet_list:
            b = raw(p)
            # Split frame
            frame = b.hex()
            frameSplit = frame.split()

            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)

            udp_protocol = str(frame[46] + frame[47])

            if(start_frame == 1 and (src_port == main_port or dst_port == main_port) and udp_protocol == '11'):
                actual_frames.append(p)
                frame_numbers.append(frame_number)
                tftp_numbers.append(arr_number[pom2])
                pom = pom + 1

            if(str(dst_port) == protocol_port and start_frame == 0):
                actual_frames.append(p)
                main_port = src_port
                start_frame = 1
                frame_numbers.append(frame_number)
                pom = pom + 1
                tftp_numbers.append(arr_number[pom2])



            pom2 = pom2 + 1

            frame_number = frame_number + 1

        tftp_frames.append(actual_frames)
        pom2 = 0
        print(len(tftp_frames))

        pom2 = 0
        for p in packet_list:
            b = raw(p)
            # Split frame
            frame = b.hex()
            frameSplit = frame.split()

            src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
            dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)

            if not(src_port == main_port or dst_port == main_port):
                new_arr.append(p)
                new_arr_numbers.append(arr_number[pom2])

            pom2 = pom2 + 1

        comms.append(actual_frames)
        number_tftp_frame = number_tftp_frame - 1
        udp_frames(new_arr, file_name, protocol_port, protocol_name, frame_number, tftp_frames, number_tftp_frame, new_arr_numbers, tftp_numbers, comms)

    else:
        # pom2 = 0
        # for packet in tftp_frames:
        #     for p in packet:
        #         b = raw(p)
        #         Split frame
                # frame = b.hex()
                # frameSplit = frame.split()
                #
                # src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                # dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                #
                # print(str(tftp_numbers[pom2]) + ": " + str(src_port) + " + " + str(dst_port))
                # pom2 = pom2 + 1
            #
            # print("-------")
        data = {"name": "PKS2022/23", "pcap_name": fileName, "filter_name": protocol_name, "complete_comms": [] }
        pom = 0
        comm_number = 1

        for packet in comms:
            frames = []
            src_dst = 0
            for p in packet:
                b = raw(p)
                frame = b.hex()
                frameSplit = frame.split()

                main_src_port = int((frame[68] + frame[69] + frame[70] + frame[71]), 16)
                main_dst_port = int((frame[72] + frame[73] + frame[74] + frame[75]), 16)
                # print(str(number_frames[pom]) + ": " + flags[pom2])

                # destination mac
                dst_mac = str(frame[0]) + str(frame[1]) + ':' + str(frame[2]) + str(frame[3]) + ':' + str(frame[4]) + str(frame[5]) + ':' + str(frame[6]) + str(frame[7]) + ':' + str(frame[8]) + str(frame[9]) + ':' + str(frame[10]) + str(frame[11])
                # source mac
                src_mac = str(frame[12]) + str(frame[13]) + ':' + str(frame[14]) + str(frame[15]) + ':' + str(frame[16]) + str(frame[17]) + ':' + str(frame[18]) + str(frame[19]) + ':' + str(frame[20]) + str(frame[21]) + ':' + str(frame[22]) + str(frame[23])

                # get frame lenght
                frameLenght = int(len(p))

                # Get frame medium
                if(frameLenght > 60):
                    frameMedium = int(len(p)) + 4
                else:
                    frameMedium = 64

                # Hexa frame
                hexaFrame = ''
                i = 1;
                for z in frame:
                    if not(i%32==0):
                        if(i != len(frame)):
                            if(i%2 == 0):
                                hexaFrame += z + " "
                                # print(z, end=" ")
                            else:
                                hexaFrame += z
                                # print(z, end="")
                    if(i == len(frame)):
                        hexaFrame += z + "\n"
                        break
                    if(i%32 == 0):
                        hexaFrame += z + "\n"
                        # print(z,  end="\n")
                    i = i+1

                srcIP = str(int((frame[52] + frame[53]), 16)) + "." + str(int((frame[54] + frame[55]), 16)) + "." + str(int((frame[56] + frame[57]), 16)) + "." + str(int((frame[58] + frame[59]), 16))
                dstIP = str(int((frame[60] + frame[61]), 16)) + "." + str(int((frame[62] + frame[63]), 16)) + "." + str(int((frame[64] + frame[65]), 16)) + "." + str(int((frame[66] + frame[67]), 16))

                if(src_dst == 0):
                    comm_src = srcIP
                    comm_dst = dstIP
                    src_dst = 1

                packet_data = {"frame_number": tftp_numbers[pom], "len_frame_pcap": frameLenght, "len_frame_medium": frameMedium,
                               "frame_type": "Ethernet II", "src_mac": src_mac, "dst_mac": dst_mac, "ether_type": "IPv4", "src_ip": srcIP,
                               "dst_ip": dstIP, "protocol": "TCP", "src_port": main_src_port, "dst_port": main_dst_port,
                               "app_protocol": protocol_name, "hexa_frame": ruamel.yaml.scalarstring.LiteralScalarString(hexaFrame)}
                frames.append(packet_data)
                pom = pom + 1
            comm = {"number_comm": comm_number, "src_comm": comm_src, "dst_comm": comm_dst, "packets": frames}
            comm_number = comm_number + 1
            data["complete_comms"].append(comm)



        yaml = ruamel.yaml.YAML()
        with open('out.yaml', 'w') as f:
            data = yaml.dump(data, f)


# main
option = input("Vyber si moznost: \n"
               "1 - vypis vsetkych ramcov\n"
               "2 - protokol s komunikaciou so spojenim (TCP)\n"
               "3 - protokol s komunikaciou bez spojenia (UDP)\n")

if(option == '1'):
    fileName = input("Zadaj nazov suboru: ")
    file = openPcapFile(fileName);
    write_all_frames(file, fileName)
if(option == '2'):
    protocol = input("Zadaj protokol (HTTP, HTTPS, TELNET, SSH, FTP-CONTROL, FTP-DATA):")
    fileName = input("Zadaj nazov suboru: ")
    file = openPcapFile(fileName);
    tcp_protocols(file, fileName, protocol)
if(option == '3'):
    protocol = input("Zadaj protokol (TFTP): ")
    fileName = input("Zadaj nazov suboru: ")
    file = openPcapFile(fileName)
    udp_protocols(file, fileName, protocol)
# sort_keys = False




