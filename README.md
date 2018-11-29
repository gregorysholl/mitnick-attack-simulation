# Mitnick Attack Simulation

This code was developed for an assignment of the Computer & Network Security course at Vrije Universiteit Amsterdam.

The assignment was to simulate an [attack](http://wiki.cas.mcmaster.ca/index.php/The_Mitnick_attack) perfomed by Kevin Mitnick into Tsutomu Shimomure's X-Terminal.

The idea was to exploit the trust relationship between `x-terminal` and `server`. The exploit should allow untrusted sources to connect to `x-terminal`. After logging into the `x-terminal`, a certain file would be located at the home directory which should be retrieved.

The `server` was running a custom daemon which would simulate a SYN-flood attack. The daemon would examine TCP SYN packets sent to port 513:
- When 10 packets with `disable` in the payload were received, it would block further interations at port.
- When 1 packet with `enable` in the payload was received, it would unblock future interations at the port.

For each student to be able to reproduce and test the exploit, 3 (three) VMs were created: `attacker`, `x-terminal` and `server`.
