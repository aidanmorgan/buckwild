# spread-spectrum-driver
A completely unnecessary and pointless network driver for linux, this only exists for personal learning purposes and should NEVER be used for any reason.

This driver implements a port-hopping network interface, inspired by the concept of [frequency hopping](https://en.wikipedia.org/wiki/Frequency-hopping_spread_spectrum) from radio transmission (specifically [HAVE QUICK](https://en.wikipedia.org/wiki/Have_Quick)) where a reliable clock source and "word of the day" are combined to create a pseudorandom port mapping for the transmission and receiving of data.

```shell
docker run -it --platform linux/amd64 -v .:/root/dev  ubuntu:latest bash
```

```shell
apt install -y software-properties-common lsb-release
apt install linux-headers-$(uname -r)

```