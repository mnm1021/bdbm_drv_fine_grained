sudo mkdir -p /usr/share/bdbm_drv
sudo touch /usr/share/bdbm_drv/ftl.dat
sudo touch /usr/share/bdbm_drv/dm.dat

sudo insmod ../../devices/ocssd/risa_dev_ocssd.ko
sudo insmod robusta_drv.ko
sudo mkfs -t ext4 -b 4096 /dev/robusta
sudo mount -t ext4 -o discard /dev/robusta /media/robusta
