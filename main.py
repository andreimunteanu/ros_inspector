from __future__ import print_function
import os,sys,nfqueue,socket
from scapy.all import *
import random
from cStringIO import StringIO
import struct
import rospy
import numpy
import PyKDL
from tf import transformations
from tf_conversions import posemath
from std_msgs.msg import String, Bool, Float32, Empty
from geometry_msgs.msg import Pose, PoseStamped, Vector3, Quaternion, Wrench, WrenchStamped, TwistStamped
from sensor_msgs.msg import JointState, Joy
from netfilterqueue import NetfilterQueue

from subprocess import PIPE
import subprocess as sp
import re

import logging
logging.basicConfig()
logger = logging.getLogger(__name__)

logger.setLevel(logging.DEBUG)

list_of_nodes_cmd = ['rosnode', 'list'] 

pid_of_node_cmd = ['rosnode', 'info']

tcp_port_cmd = 'netstat --listening --program | grep '

tcp_port_cmd_all = 'netstat --all --program | grep 4507'

bind_address_cmd = 'iptables -A OUTPUT -p tcp --sport {0} -j NFQUEUE --queue-num 1'

unbind_address_cmd = 'iptables -D OUTPUT -p tcp --sport {0} -j NFQUEUE --queue-num 1'

# sudo iptables -D OUTPUT -p tcp --sport 5775 -j NFQUEUE --queue-num 1

list_iptables_cmd = ['iptables', '-L']

topic_list_cmd = ['rostopic', 'list']

topic_type_cmd = ['rostopic', 'type']

show_msg_cmd = ['rosmsg', 'show']

data_classes_list = ['String', 'Empty','Quaternion', 'Wrench', 'WrenchStamped', 'TwistStamped', 'Bool', 'Float32', 'PoseStamped', 'Pose','Vector3']#,'JointState', 'Joy']

data_classes_dict = {'String' : None, 'Empty' : None, 'Quaternion' : None, 
                'Wrench' : None, 'WrenchStamped' : None, 
                'TwistStamped' : None, 'Bool' : None, 'Float32' : None, 
                'PoseStamped' : None, 'Pose' : None, 'Vector3' : None }


data_network = None
packets = []
ports_to_esclude = {}
binded_ports = []

def String_fun(previous_data_type, current_data_type, data):
    return None

def Empty_fun(previous_data_type, current_data_type, data):
    return None

def Quaternion_fun(previous_data_type, current_data_type, data):
    return None

def Wrench_fun(previous_data_type, current_data_type, data):
    return None

def WrenchStamped_fun(previous_data_type, current_data_type, data):
    return None

def TwistStamped_fun(previous_data_type, current_data_type, data):
    return None

def Bool_fun(previous_data_type, current_data_type, data):
    return None

def Float32_fun(previous_data_type, current_data_type, data):
    return None

def PoseStamped_fun(previous_data_type, current_data_type, data):
    return None

def Pose_fun(previous_data_type, current_data_type, data):
    """
    TODO with PyKDL.Frame
    """
    print ('Pose :')
    print ('current ' + str(current_data_type))
    print ('previous ' + str(previous_data_type))
    c_pos = current_data_type.position
    c_orie = current_data_type.orientation
    
    p_pos = previous_data_type.position
    p_orie = previous_data_type.orientation

    #ar_pos = numpy.array((c_pos.x-p_pos.x,c_pos.y-p_pos.y,c_pos.z-p_pos.z))
    #ar_orie = numpy.array((c_orie.x-p_orie.x, c_orie.y-p_orie.y, c_orie.z-p_orie.z, c_orie.w-p_orie.w))

    
    ar_pos = numpy.array((c_pos.x,c_pos.y,c_pos.z))
    ar_orie = numpy.array((c_orie.x, c_orie.y, c_orie.z, c_orie.w))

    norm_pos = numpy.linalg.norm(ar_pos)
    norm_orie = numpy.linalg.norm(ar_orie)
    print (str(norm_pos) + ' ' + str(norm_orie))
    if data['accumulated'] is None:
        data['accumulated'] = []
    else:
        data['accumulated'].append([norm_pos, norm_orie])
    return [norm_pos, norm_orie]

def Vector3_fun(previous_data_type, current_data_type, data):
    return None




data_classes_funs = {'String' : String_fun, 'Empty' : Empty_fun,'Quaternion' : Quaternion_fun,'Wrench' : Wrench_fun,
                    'WrenchStamped' : WrenchStamped_fun,'TwistStamped' : TwistStamped_fun,
                    'Bool' : Bool_fun,'Float32' : Float32_fun,'PoseStamped' : PoseStamped_fun,
                    'Pose' : Pose_fun,'Vector3' : Vector3_fun}

def _exec_command(cmd, shell=False):
    
    p = sp.Popen(cmd ,shell=shell, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out

def get_list_of_nodes_cmd():
    names = _exec_command(list_of_nodes_cmd)
    return names.split('\n')[:-1]

def get_pid_and_host(node_name):
    out = _exec_command(pid_of_node_cmd + [node_name])
    logger.debug('-----node info------ \n' + out)
    m = re.search('(?<=Pid: )\d+', out)
    pid = m.group(0)

    m = re.search('(?<=contacting node )(.*)(?= \.\.\.)',out)
    host = m.group(0)

    return (pid,host)

def get_src_tcp_ports(pid, all=False):
    """TO DO: all"""
    if len(sys.argv) > 1 and sys.argv[1] == 'all':
        cmd = tcp_port_cmd_all
    else:
        cmd = tcp_port_cmd

    out = _exec_command(cmd+pid,True)
    logger.debug('-----ports----- \n' + out)
    
    pattern_tcp = 'tcp        0      0 \*:'
    pattern_udp = 'udp        0      0 \*:'

    m = re.findall('(?<='+pattern_tcp+')\d+', out)
    result = {'tcp' : m, 'udp':None}
    
    m = re.search('(?<='+pattern_udp+')\d+', out) 
    if not(m is None):
        result['udp'] = m.group(0)

    return result


def get_network_structure():
    nodes_data = {}
    list_of_nodes_cmd = get_list_of_nodes_cmd()
    for i in range(len(list_of_nodes_cmd)):
        logger.debug('node -> '+str(i) + ' ' + list_of_nodes_cmd[i])
        nodes_data[list_of_nodes_cmd[i]] = {'pid': '','host':'' , 'ports' : {'xmlrpc':None,'tcp':None, 'udp':None}}
        
        pid, host = get_pid_and_host(list_of_nodes_cmd[i])
        nodes_data[list_of_nodes_cmd[i]]['pid'] = pid
        nodes_data[list_of_nodes_cmd[i]]['host'] = host
        
        ports = nodes_data[list_of_nodes_cmd[i]]['ports']
        ports_data = get_src_tcp_ports(pid)
        
        if ports_data['tcp'][0] in host:
            ports['xmlrpc'] = ports_data['tcp'][0]
            ports['tcp'] = ports_data['tcp'][1]
        else:
            ports['xmlrpc'] = ports_data['tcp'][1]
            ports['tcp'] = ports_data['tcp'][0]
        if not(ports_data['udp'] is None):
            ports['udp'] = ports_data['udp']

        logger.debug('data - ' + str(nodes_data[list_of_nodes_cmd[i]]))
    return nodes_data


def test_basics():
    list_of_nodes_cmd = get_list_of_nodes_cmd()

    print('active nodes')
    for i in range(len(list_of_nodes_cmd)):
        print (str(i) + ' ' + list_of_nodes_cmd[i])

    index = int(raw_input('choose one! '))
    
    pid = get_pid_and_host(list_of_nodes_cmd[index])

    print ('node -->' + list_of_nodes_cmd[index])
    print ('pid: ' + pid + ' ports: ' + str(get_src_tcp_ports(pid)))


def get_topic_list():
    out = _exec_command(topic_list_cmd)
    logger.debug('topic list: \n' + out)
    return out.split('\n')

def get_topic_type(topic):
    out = _exec_command(topic_type_cmd + [topic])
    logger.debug(topic + ' type: '+ out)
    if len(out.split('\n')) > 2:
        raise Exception('missing some types')
    return out.split('\n')[0]

def show_msg(msg):
    out = _exec_command(show_msg_cmd + [msg])
    logger.debug(msg + ' show: '+ out)
    return out.split('\n')[:-2]

def topic_analyzer():
    topic_list = get_topic_list()
    data = {}

    for topic in topic_list:
        topic_type = get_topic_type(topic)
        data[topic] = {'type': {topic_type: show_msg(topic_type)}}

    return data

def bind_address(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO for dst and ips"""
    global binded_ports
    binded_ports.append(src_port)
    
    out = _exec_command(bind_address_cmd.format(int(src_port)),shell=True)


def unbind_address(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO"""
    try:
        global binded_ports
        binded_ports.remove(src_port)
    except:
        pass

    out = _exec_command(unbind_address_cmd.format(src_port), shell=True)


structure = {}
"""structure = {src: 'name', dst: 'name'
                comunication : {topci(or type): topic_name, src_port : 'src_port', dst_port:'dst_port'}
                }"""
"""nb jointState mi da la string vuota <_<"""

def get_data_class(raw_data):

    types = {}

    for data_class in data_classes_list:
        
        try:
            types[data_class] = None
            b = StringIO()

            b.write(raw_data)
            #print 'initial len -> %d '%len(str(packet))
            b.seek(0)
            (size,) = struct.unpack('<I', b.read(4))
            get_class = lambda x: globals()[x]
            msg = get_class(data_class)()
            b.seek(4)
            msg.deserialize(b.read(size))
            #print ("current msg -> %s"%msg)
            types[data_class] = msg
            b.close()
        except:
            pass

    return types

def infer_data_type(key, data_types):
    global ports_to_esclude
    ports_to_esclude[key]['counter'] = ports_to_esclude[key]['counter'] + 1

    ports_to_esclude[key]['previous_data_types'] = ports_to_esclude[key]['current_data_types']
    ports_to_esclude[key]['current_data_types'] = data_types

    compute_accumulated(ports_to_esclude[key])


def compute_accumulated(data):
    previous_data_types = data['previous_data_types']
    current_data_types = data['current_data_types']

    for data_class in data_classes_list:
        if not(previous_data_types[data_class] is None or current_data_types[data_class] is None):
            fun = data_classes_funs[data_class]
            result = fun(previous_data_types[data_class], current_data_types[data_class],data)
    #return result

def analyze_packet(packet):
    global ports_to_esclude
    if not(Raw in packet and TCP in packet):
        return

    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if not((src_port, dst_port) in ports_to_esclude.keys()) or ports_to_esclude[(src_port, dst_port)]['counter'] != 5: 
                print ('---------------------------------------------')
                print ('node ' + str(get_node_from_port(src_port)))
                print ('node ' + str(get_node_from_port(dst_port)))
                print ("packet from: {0} to {1}".format(src_ip,dst_ip))
                print ("ports      {0}   to {1}".format(src_port, dst_port))

                data_and_types = get_data_class(packet[Raw].load)

                #print 'type: %r'%(data_and_types)
                print ('----------------------------------------------')

                
                if not((src_port, dst_port) in ports_to_esclude.keys()):
                    
                    ports_to_esclude[(src_port,dst_port)] = {'accumulated' : None,#dict(data_classes_dict), 
                                                                'current_data_types' : data_and_types , 
                                                                'previous_data_types' : None, 
                                                                'counter' : 0}
                else:
                    infer_data_type((src_port,dst_port), data_and_types)
                    #ports_to_esclude[(src_port,dst_port)].append(data_and_types)
                    

    except:
        raise

def get_node_from_port(port):
    if data_network is None:
        return None
    for key, value in data_network.items():

        if value['ports']['tcp'] == str(port):
            return key 
    return None

def analyze_and_built_structure(data_of_nodes):
    _filter = 'host 127.0.0.1 or host 127.0.1.1'
    global ports_to_esclude
    
    for i in range(2):
        #log.debug('i ->  {0} ports excluded: \n'.format(i) + str(ports_to_esclude) )
        port_filter = ''

        for ports in ports_to_esclude.keys():
            port_filter = port_filter + ' and not port {0} and not {1}'.format(ports[0],ports[1])

        sniff(count=1000,filter=_filter ,prn=analyze_packet)

    s = ''
    for k, v in ports_to_esclude.items():
        s = (s + '\n\n'+ str(k) + ' : (' + str(get_node_from_port(k[0])) + ', ' + str(get_node_from_port(k[1])) + ')'
                + '\n\tcounter -> ' + str(v['counter'])
                + '\n\tcurrent_data_types -> ' + str(len(v['current_data_types']))
                + '\n\tprevious_data_types -> ' + str(len(v['previous_data_types']))
                + '\n\t' + 'accumulated ->\n' + str(v['accumulated'])
            )

    logger.debug(' ports analyzed:  {0} \n'.format(s))
    structure = {}

def print_results_from_packets():
    global ports_to_esclude

    for k,v in ports_to_esclude.items():
        if not(v['accumulated'] is None):

            if(get_node_from_port(k[0]) is None and get_node_from_port(k[1]) is None):
                _id = k
            else:
                _id = '({0}: {1}, {2}: {3})'.format(get_node_from_port(k[0]),k[0],get_node_from_port(k[1]),k[1])

            p = [x[0] for x in v['accumulated']]
            o = [x[1] for x in v['accumulated']]
            print ('-connection id: {0}\n\tposition norms: {1}:\
                \n\torientation norms: {2}\n'.format(_id,p,o))



def analyze_packet_wrapper():
    analyze_and_built_structure("")

def bind_address_wrapper():
    print ("Insert port to bind")
    port = raw_input(" -- > ")
    bind_address(int(port))

def unbind_address_wrapper():
    print ("Insert port to unbind")
    port = raw_input(" -- > ")
    unbind_address(int(port))

def bind_and_clear():

    for port in binded_ports:
        unbind_address(int(port))

    bind_address_wrapper()


def print_network_structure():
    network_structure = get_network_structure()
    global data_network
    data_network = network_structure

    for name, value in network_structure.items():
        print (name)
        print (value)
        print ('')

def print_data_network():
    if data_network is None:
        return
    global data_network

    for name, value in data_network.items():
        print (name)
        print (value)
        print ('')

def print_current_binded():
    print ('Current rules: ')
    global binded_ports
    print ('ports ' + str(binded_ports))
    out = _exec_command(list_iptables_cmd)
    print (out)
    """
    for port in binded_ports:
        print bind_address_cmd.format(port)
    """

def sniff_on_pcap():
    """PERMISSIONS"""
    """or only wireshark"""
    try:
        _filter = ''

        def _prn(packet):
            pass

        pkts = sniff(filter=_filter, prn=_prn)
    except:
        raise
    print('\n')    
    print ('Interupted!\nCaptured -> %d packets'%len(pkts))
    #print ('Summary:')
    #print (pkts.summary())
    logger.debug('Writing packets on "ros.cap"')
    try:
        pkts_from_file = rdpcap('ros.cap')
        pkts.extend(pkts_from_file)
    except IOError:
        pass
    wrpcap('ros.cap',pkts)

def find_pose_from_file():
    _filter = 'host 127.0.0.1 or host 127.0.1.1'
    def structure_data(packet):
        if not(Raw in packet and TCP in packet):
            return
        raw_data = packet[Raw].load
        data = None
        try:
            data_class = 'Pose'
            b = StringIO()

            b.write(raw_data)
            #print 'initial len -> %d '%len(str(packet))
            b.seek(0)
            (size,) = struct.unpack('<I', b.read(4))
            get_class = lambda x: globals()[x]
            msg = get_class(data_class)()
            b.seek(4)
            msg.deserialize(b.read(size))
            #print ("current msg -> %s"%msg)
            data = msg
            b.close()
        except:
            return

        c_pos = data.position
        c_orie = data.orientation
        ar_pos = numpy.array((c_pos.x,c_pos.y,c_pos.z))
        ar_orie = numpy.array((c_orie.x, c_orie.y, c_orie.z, c_orie.w))

        norm_pos = numpy.linalg.norm(ar_pos)
        norm_orie = numpy.linalg.norm(ar_orie)

        if norm_orie == 1.0:
            print('-'*60)
            print('ports: ({0},{1}) '.format(packet[TCP].sport, packet[TCP].dport))
            print('norm_pos: {0}'.format(norm_pos))
            print('norm_orie: {0}'.format(norm_orie))
            print('-'*60)


    pkts = sniff(filter=_filter, prn=structure_data, offline='ros.cap')


options = ("""
            1 - > print network strucure           q - > quit
            2 - > print old data
            3 - > sniff packets                    s - > sniff and store on pcap file
            4 - > get details of packets           g - > get details from file
            5 - > bind address
            6 - > unbind address
            7 - > bind and remove other bindings
            8 - > print current binded 
            """)

interactive_options = {
                        '1': print_network_structure,
                        '2': print_data_network,
                        '3': analyze_packet_wrapper,
                        '4': print_results_from_packets,
                        '5': bind_address_wrapper,
                        '6': unbind_address_wrapper,
                        '7': bind_and_clear,
                        '8': print_current_binded,
                        's': sniff_on_pcap,
                        'g': find_pose_from_file,
                        'q': sys.exit
}

def run_interactive_prompt():
    while True:
        print (options)
        try:
            option = raw_input(" -- > ")
            o = option
            f = interactive_options[o]
            print ('-'*120)
            f()
        #except KeyError:
        #    print ('no option')
        except:
            raise

"""
launch as super user

NOTES:
add: info about xmlrpc servers
"""

def main():
    run_interactive_prompt()
    #test_basics()
    """
    network_structure = get_network_structure()
    
    for name, value in network_structure.items():
        print name
        print value
        print ''
    """
    #analyze_and_built_structure("")

if __name__ == '__main__':
    sys.exit(main())
