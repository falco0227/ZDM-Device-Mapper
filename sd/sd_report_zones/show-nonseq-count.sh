#!/bin/bash

if [ $# -eq 0 ]
then
	echo "usage: $0 [-c] drive-letters"
	exit 0
fi

continuous=0

for i in $*
do
	if [ $i == "-c" ]
	then
		continuous=1
	elif [[ $i == -* ]]
	then
		echo "ignoring unrecognized option $i"
	else
		drives="$drives $i"
	fi
done

# Force sudo validation early to avoid interference with output
sudo echo -n

trap "{ exit 0; }" SIGINT SIGTERM

while [ 1 ]
do
	for drive_id in $drives
	do
		echo -n "/dev/sd$i: "

		sd_device=/dev/sd${drive_id}
		dev=/sys/block/sd${drive_id}
		devsz=`cat ${dev}/size` # Size in 512k blocks

		echo ${sd_device} ${dev} ${devsz}

		zonecount=$(( ( ( (${devsz} / 0x80000) + 8190) / 8191) ))
		echo "Number of megazones on drive:" ${zonecount}
		offset=0

		while [ ${offset} -lt ${zonecount} ]
		do
			echo /dev/sd${drive_id} "Z#" $((1024 * ${offset})) query upto 8190 zones.
			echo sudo sd_report_zones ata \
				$((0x80000 * 1024 * ${offset})) \
				/dev/sd${drive_id}
			sudo ./sd_report_zones ata \
				$((0x80000 * 1024 * ${offset})) \
				/dev/sd${drive_id}
			offset=$((${offset} + 1))
		done
	done

	if [ $continuous -eq 0 ]
	then
		break;
	else
		sleep 5
	fi
done
