# Description

[Fluent Bit](https://fluentbit.io) input plugin that collects disk usage information from Linux hosts.

This plugin **will only work** on hosts running Linux, because it relies on `/proc/diskstats` file from [Procfs](https://en.wikipedia.org/wiki/Procfs).

# Requirements

- Docker
- Docker image `fluent-beats/fluent-bit-plugin-dev`

# Build
```bash
./build.sh
```

# Test
```bash
./test.sh
 ```

# Design

This plugin was desined to collect data from any mounted Linux `diskstats` proc file.

It can be used to collect host disk stats, even if Fluent Bit is running inside a container, which is not achiavable using **native** Fluent Bit `disk` plugin.

> Potentially LXCFS could bypass that without requiring a custom plugin

## Configurations

This input plugin can be configured using the following parameters:

 Key                    | Description                                   | Default
------------------------|-----------------------------------------------|------------------
 dev_name               | Device name to limit the target. (e.g. sda). If not set, gathers information from all of disks and partitions.                                                            | null
 interval_sec           | Interval in seconds to collect data           | 1
 interval_nsec          | Interval in nanoseconds to collect data       | 0
 proc_path              | Path to look for diskstats file               | /proc

