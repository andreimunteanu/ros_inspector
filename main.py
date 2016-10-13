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

data_network = None
packets = []
ports_to_esclude = {}
binded_ports = []


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
data_classes = ['String', 'Empty','Quaternion', 'Wrench', 'WrenchStamped', 'TwistStamped', 'Bool', 'Float32', 'PoseStamped', 'Pose','Vector3']#,'JointState', 'Joy']

"""nb jointState mi da la string vuota <_<"""

def get_data_class(raw_data):

    types = {}

    for data_class in data_classes:
        
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
            if not((src_port, dst_port) in ports_to_esclude.keys()) or len(ports_to_esclude[(src_port, dst_port)]) != 2: 
                print ('---------------------------------------------')
                print ('node ' + str(get_node_from_port(src_port)))
                print ('node ' + str(get_node_from_port(dst_port)))
                print ("packet from: {0} to {1}".format(src_ip,dst_ip))
                print ("ports      {0}   to {1}".format(src_port, dst_port))

                data_and_types = get_data_class(packet[Raw].load)

                #print 'type: %r'%(data_and_types)
                print ('----------------------------------------------')

                
                if not((src_port, dst_port) in ports_to_esclude.keys()):
                    ports_to_esclude[(src_port,dst_port)] = [data_and_types]
                else:
                    ports_to_esclude[(src_port,dst_port)].append(data_and_types)
                    

    except:
        raise

def get_node_from_port(port):
    if data_network is None:
        return None
    for key, value in data_network.items():

        if value['ports']['tcp'] == str(port):
            return key 
    return None

def infer_data_type(data):
    pass

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
        s = s + ' '+ str(k) + ' : ' + str(len(v)) 

    logger.debug(' ports analyzed:  {0} \n'.format(s))
    structure = {}

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
options = ("""
            1 - > print network strucure           q - > quit
            2 - > print old data
            3 - > sniff packets
            4 - > bind address
            5 - > unbind address
            6 - > bind and remove other bindings
            7 - > print current binded 
            """)

interactive_options = {
                        '1': print_network_structure,
                        '2': print_data_network,
                        '3': analyze_packet_wrapper,
                        '4': bind_address_wrapper,
                        '5': unbind_address_wrapper,
                        '6': bind_and_clear,
                        '7': print_current_binded,
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
        except KeyError:
            print ('no option')
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
