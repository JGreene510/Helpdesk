'use strict';
// Test helper: simulates a sandbox that forbids reading the machine's network
// interfaces. This is what systemd's RestrictAddressFamilies does when
// AF_NETLINK is not allowed: Node then throws from os.networkInterfaces().
const os = require('node:os');
os.networkInterfaces = () => { throw new Error('uv_interface_addresses returned Unknown system error 97 (Unknown system error 97)'); };
