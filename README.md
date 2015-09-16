
## Introduction

Device Mapper for Zoned based devices: ZDM for short.

This project aims to present a traditional block device for Host Aware and
Host Managed drives.

## Architecture

ZDM treats a zoned device as a collection of 1024 zones [256GiB], referred to internally as 'megazones'. The last megazone may be less than 1024 zones in size. Each megazone reserves a minimum 8 zones for meta data and over-provisioning [less than 1% of a disk].

Device trim [aka discard] support is enabled by default. It is recommended to increase the over-provision ratio when discard support is disabled.

The initial implementation focuses on drives with same sized zones of 256MB which is 65536 4k blocks. In future the zone size of 256MB will be relaxed to allow any size of zone as long as they are all the same.
Internally all addressing is on 4k boundaries. Currently a 4k PAGE_SIZE is assumed. Architectures with 8k (or other) PAGE_SIZE values have not been tested and are likely broken at the moment.

Host Managed drives should work if the zone type at the start of the partition is Conventional, or Preferred.

## Software Requirements

  - Current Linux Kernel (4.2) with ZDM patches
  - Recommended: sg3utils (1.41 or later)

## Caveat Emptor - Warning

  - ZDM software is a work in progress. It is currently intended for testing
    and reference. It may crash, hang, or worse you could lose data!

## Current restrictions/assumptions

  - Zone size (256MiB).
  - 4k page / block size.
  - Host Aware, Conventional
  - Host Managed w/partition starting on a Conventional, or Preferred zone type.
  - Currently 1 GiB of RAM per drive is recommeneded.

## Userspace utilities
  - zdm-tools: zdmadm, zdm-status, zdm-zones ...
  - zbc/zac tools (sd_* tools)

## Typical Setup

  - Reset all WPs on drive:
```
      sg_reset_wp --all /dev/sdX
```
or
```
      sd_reset_wp -1 /dev/sdX
```
or
```
      sd_reset_wp ata -1 /dev/sdX
```

  - Partition the drive to start the partition at a WP boundary.
```
      parted /dev/sdX
      mklabel gpt
      mkpart primary 256MiB 7452GiB
```

  - Place ZDM drive mapper on /dev/sdX
```
      zdmadm -c /dev/sdX1
```

  - Format:
```
      mkfs -t ext4 -E discard /dev/mapper/zdm_sdX1
```
or
```
      mkfs -t ext4 -b 4096 -g 32768 -G 32 \
        -E offset=0,num_backup_sb=0,packed_meta_blocks=1,discard \
        -O flex_bg,extent,sparse_super2 /dev/mapper/zdm_sdX1
```

  - Mounting the filesystem.
```
      mount -o discard /dev/mapper/zdm_sdX1 /mnt/zdm_sdX1
```
 
Building:
  - Normal kernel build with CONFIG_DM_ZONED and CONFIG_BLK_ZONED_CTRL enabled.

## Standards Versions Supported

ZAC/ZBC standards are still being developed. Changes to the command set and
command interface can be expected before the final public release.

## License

ZDM is distributed under the terms of GPL v2 or any later version.

ZDM and all and all utilities here in are distributed "as is," without technical
support, and WITHOUT ANY WARRANTY, without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Along with ZDM, you should
have received a copy of the GNU General Public License.
If not, please see http://www.gnu.org/licenses/.

## Contact and Bug Reports

 - Adrian Palmer [adrian.palmer@seagate.com](mailto:adrian.palmer@seagate.com)
 
