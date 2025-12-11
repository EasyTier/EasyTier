//先处理逻辑，声明变量并执行条件判断
let api = "";
const ETHost = "easytier.cn";
// 备用选项（按需取消注释）
// const defaultPort = location.protocol === 'https:' ? '443' : '80';
// const baseUrl = location.protocol + '//' + location.hostname + ':' + (location.port || defaultPort);

// 根据host判断赋值
if (location.host === ETHost) {
    api = "https://config-server.easytier.cn";
} else {
    api = location.origin;
    // 备用选项（连接失败时替换）
    // api = baseUrl;
}

// 将处理好的值赋值给window.apiMeta对象
window.apiMeta = {
    api_host: api // 正确的对象键值对写法
};
