window.apiMeta = {
    api_host: location.origin //使用 location.origin 代替原本固定域名
    // 备用选项，使用默认的80端口建立面板导致连接失败时取消注释以下内容
    // const defaultPort = location.protocol === 'https:' ? '443' : '80';
    // const baseUrl = location.protocol + '//' + location.hostname + ':' + (location.port || defaultPort);
    // api_host: baseUrl
}
