from mininet.net import Mininet
from mininet.topo import Topo

original_build = Mininet.build
def build(self):
   original_build(self)
   h1 = self.nameToNode['h1']
   h2 = self.nameToNode['h2']
   h1.cmd('arp -i h1-eth0 -s 10.0.1.2 00:00:00:00:00:02')
   h2.cmd('arp -i h2-eth0 -s 10.0.1.1 00:00:00:00:00:01')
Mininet.build = build

class MyTopo( Topo ):
   def build( self ):
      "Create custom topo."
      # Add hosts and switches. h1 -- s1 -- s2 -- h2
      h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')
      h2 = self.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:00:02')
      s1 = self.addSwitch('s1')
      s2 = self.addSwitch('s2')
      # Add links
      self.addLink(h1, s1)
      self.addLink(s1, s2)
      self.addLink(s2, h2)

topos = { 'mytopo': ( lambda: MyTopo() ) }

