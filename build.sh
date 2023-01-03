export PATH="/home/cn1396/.toolchain/gcc-arm-11.2-2022.02-x86_64-arm-none-linux-gnueabihf/bin/:$PATH"
export CROSS_COMPILE=arm-none-linux-gnueabihf-
export ARCH=arm
export LOADADDR=0x00008000
# make distclean
make xilinx_zynq_defconfig
make -j8
# make all
# #make modules_install INSTALL_MOD_PATH=../rootfs
make -j8 uImage
#make dtbs

rm -rf output
mkdir output

cp arch/arm/boot/uImage output
cp arch/arm/boot/dts/zynq-zc706.dtb output/system.dtb
# make modules
