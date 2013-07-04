# Shared-storage based death #

A highly reliable fencing or Shoot-the-other-node-in-the-head (STONITH) mechanism that works by utilizing shared storage.

The component works with Pacemaker clusters. (Currently, it is only
tested on clusters using the "old" plugin to corosync, not yet the MCP
code. Patches are welcome.)

Please see https://github.com/l-mb/sbd/blob/master/man/sbd.8.pod for the full documentation.

