# easytier_docker
Easytier docker version source code can be run through the command line or configuration file configuration file priority</br> 
## Configuration file run
docker run -itd --name easytier -v ./config.yaml:/config.yaml --device=/dev/net/tun --net=host --restart=always --cap-add=NET_ADMIN --cap-add=SYS_ADMIN registry.cn-hangzhou.aliyuncs.com/dubux/easytier:latest </br>
## Run command line parameters
docker run -itd --name easytier -e COMMNAD="" --device=/dev/net/tun --net=host --restart=always --cap-add=NET_ADMIN --cap-add=SYS_ADMIN registry.cn-hangzhou.aliyuncs.com/dubux/easytier:latest </br>
