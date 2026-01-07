SKIPMOUNT=false
PROPFILE=true
POSTFSDATA=true
LATESTARTSERVICE=true

set_perm_recursive $MODPATH 0 0 0777 0777

ui_print '安装完成'
ui_print '当前架构为' + $ARCH
ui_print '当前系统版本为' + $API
ui_print '安装目录为:  /data/adb/modules/easytier_magisk'
ui_print '配置文件位置:  /data/adb/modules/easytier_magisk/config/config.toml'
ui_print '如果需要自定义启动参数，可将 /data/adb/modules/easytier_magisk/config/command_args_sample 重命名为 command_args，并修改其中内容，使用自定义启动参数时会忽略配置文件'
ui_print '修改配置文件后在magisk app禁用应用再启动即可生效'
ui_print '点击操作按钮可启动/关闭热点子网转发，配合easytier的子网代理功能实现手机热点访问easytier网络'
ui_print '记得重启'
