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

list_of_nodes = ['rosnode', 'list'] 

pid_of_node = ['rosnode', 'info']

get_tcp_port = 'netstat --listening --program | grep '

get_tcp_port_all = 'netstat --all --program | grep '

bind_address = 'iptables -A OUTPUT -p tcp --dport {0} -j NFQUEUE --queue-num 1'

unbind_address = ""

def _exec_command(cmd, shell=False):
    
    p = sp.Popen(cmd ,shell=shell, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out

def get_list_of_nodes():
    names = _exec_command(list_of_nodes)
    return names.split('\n')[:-1]

def get_pid_of_node(node_name):
    out = _exec_command(pid_of_node + [node_name])
    logger.debug('-----node info------ \n' + out)
    m = re.search('(?<=Pid: )\d+', out)
    pid = m.group(0)

    return pid

def get_src_tcp_ports(pid):

    if len(sys.argv) > 1 and sys.argv[1] == 'all':
        cmd = get_tcp_port_all
    else:
        cmd = get_tcp_port

    out = _exec_command(cmd+pid,True)
    logger.debug('-----ports----- \n' + out)
    
    pattern = 'tcp        0      0 \*:'
    m = re.findall('(?<='+pattern+')\d+', out)
    port = m

    return port


def get_network_structure():
    nodes_data = {}
    list_of_nodes = get_list_of_nodes()
    for i in range(len(list_of_nodes)):
        logger.debug('node -> '+str(i) + ' ' + list_of_nodes[i])
        nodes_data[list_of_nodes[i]] = {'pid': 0, 'ports' : []}
        
        pid = get_pid_of_node(list_of_nodes[i])
        nodes_data[list_of_nodes[i]]['pid'] = pid
        
        nodes_data[list_of_nodes[i]]['ports'] = get_src_tcp_ports(pid)
        logger.debug('data - ' + str(nodes_data[list_of_nodes[i]]))
    return nodes_data

def bind_address(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO for dst and ips"""
    out = _exec_command(bind_address.format(src_port))


def unbind_address(src_port, src_ip='127.0.0.1', dst_port=None, dst_ip=None):
    """TO DO"""
    pass

def analyze_and_built_structure(data):
    pass

def test_basics():
    list_of_nodes = get_list_of_nodes()

    print 'active nodes'
    for i in range(len(list_of_nodes)):
        print str(i) + ' ' + list_of_nodes[i]

    index = int(raw_input('chose one! '))
    
    pid = get_pid_of_node(list_of_nodes[index])

    print 'node ->>' + list_of_nodes[index]
    print 'pid: ' + pid + ' ports: ' + str(get_src_tcp_ports(pid))

"""
launch as super user

NOTES:
add: info about xmlrpc servers
"""
def main():
    #test_basics()
    for name, value in get_network_structure().items():
        print name
        print value
        print ''

if __name__ == '__main__':
    sys.exit(main())
