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

bind_address_cmd = 'iptables -A OUTPUT -p tcp --dport {0} -j NFQUEUE --queue-num 1'

topic_list_cmd = ['rostopic', 'list']

topic_type_cmd = ['rostopic', 'type']

show_msg_cmd = ['rosmsg', 'show']

unbind_address_cmd = ""
packets = []
ports_to_esclude = []


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
    m = re.findall('(?<='+pattern_tcp+')\d+|(?<='+pattern_udp+')\d+', out)
    port = m

    return port


def get_network_structure():
    nodes_data = {}
    list_of_nodes_cmd = get_list_of_nodes_cmd()
    for i in range(len(list_of_nodes_cmd)):
        logger.debug('node -> '+str(i) + ' ' + list_of_nodes_cmd[i])
        nodes_data[list_of_nodes_cmd[i]] = {'pid': '','host':'' , 'ports' : []}
        
        pid, host = get_pid_and_host(list_of_nodes_cmd[i])
        nodes_data[list_of_nodes_cmd[i]]['pid'] = pid
        nodes_data[list_of_nodes_cmd[i]]['host'] = host
        
        nodes_data[list_of_nodes_cmd[i]]['ports'] = get_src_tcp_ports(pid)
        logger.debug('data - ' + str(nodes_data[list_of_nodes_cmd[i]]))
    return nodes_data


def test_basics():
    list_of_nodes_cmd = get_list_of_nodes_cmd()

    print 'active nodes'
    for i in range(len(list_of_nodes_cmd)):
        print str(i) + ' ' + list_of_nodes_cmd[i]

    index = int(raw_input('choose one! '))
    
    pid = get_pid_and_host(list_of_nodes_cmd[index])

    print 'node ->>' + list_of_nodes_cmd[index]
    print 'pid: ' + pid + ' ports: ' + str(get_src_tcp_ports(pid))


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

def bind_address_cmd(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO for dst and ips"""
    out = _exec_command(bind_address_cmd.format(src_port))


def unbind_address_cmd(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO"""
    pass

structure = {}
"""structure = {src: 'name', dst: 'name'
                comunication : {topci(or type): topic_name, src_port : 'src_port', dst_port:'dst_port'}
                }"""
data_classes = ['Pose', 'PoseStamped', 'Vector3', 'Quaternion', 'Wrench', 'WrenchStamped', 'TwistStamped', 'Bool', 'Float32', 'Empty','String']

def get_data_class(raw_data):
    for data_class in data_classes:
        try:
            b = StringIO()

            b.write(raw_data)
            #print 'initial len -> %d '%len(str(packet))
            b.seek(0)
            (size,) = struct.unpack('<I', b.read(4))
            get_class = lambda x: globals()[x]
            msg = get_class(data_class)()
            b.seek(4)
            msg.deserialize(b.read(size))
            print "current msg -> %s"%msg
            return msg,type(msg)
        except:
            raise

def analyze_packet(packet):
    if not(Raw in packet and TCP in packet):
        return

    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if not((src_port, dst_port) in ports_to_esclude): 
                print '---------------------------------------------'
                print "packet from: {0} to {1}".format(src_ip,dst_ip)
                print "ports      {0}   to {1}".format(src_port, dst_port)

                data, data_type = get_data_class(packet[Raw].load)

                print 'type: {0}'.format(data_type)
                print '----------------------------------------------'
                global ports_to_esclude
                ports_to_esclude.append((src_port,dst_port))

    except:
        raise

def analyze_and_built_structure(data):
    _filter = 'host 127.0.0.1 or host 127.0.1.1'
    global ports_to_esclude
    
    for i in range(2):
        log.debug('i ->  {0} ports excluded: \n'.format(i) + str(ports_to_esclude) )
        port_filter = ''

        for ports in ports_to_esclude:
            port_filter = port_filter + ' and not port {0} and not {1}'.format(ports[0],ports[1])

        sniff(count=1000,filter=_filter ,prn=analyze_packet)

    structure = {}


"""
launch as super user

NOTES:
add: info about xmlrpc servers
"""

def main():
    
    #test_basics()
    
    network_structure = get_network_structure()
    
    for name, value in network_structure.items():
        print name
        print value
        print ''
    
    #analyze_and_built_structure("")

if __name__ == '__main__':
    sys.exit(main())
