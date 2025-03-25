const defaultApiHost = 'https://config-server.easytier.cn';

interface ApiHost {
    value: string;
    usedAt: number;
}

const isValidHttpUrl = (s: string): boolean => {
    let url;

    try {
        url = new URL(s);
    } catch (_) {
        return false;
    }

    return url.protocol === "http:" || url.protocol === "https:";
};

const cleanAndLoadApiHosts = (): Array<ApiHost> => {
    const maxHosts = 10;
    const apiHosts = localStorage.getItem('apiHosts');
    if (apiHosts) {
        const hosts: Array<ApiHost> = JSON.parse(apiHosts);
        // sort by usedAt
        hosts.sort((a, b) => b.usedAt - a.usedAt);

        // only keep the first 10
        if (hosts.length > maxHosts) {
            hosts.splice(maxHosts);
        }

        localStorage.setItem('apiHosts', JSON.stringify(hosts));
        return hosts;
    } else {
        return [];
    }
};

const saveApiHost = (host: string) => {
    console.log('Save API Host:', host);
    if (!isValidHttpUrl(host)) {
        console.error('Invalid API Host:', host);
        return;
    }

    let hosts = cleanAndLoadApiHosts();
    const newHost: ApiHost = {value: host, usedAt: Date.now()};
    hosts = hosts.filter((h) => h.value !== host);
    hosts.push(newHost);
    localStorage.setItem('apiHosts', JSON.stringify(hosts));
};

const getInitialApiHost = (): string => {
    const hosts = cleanAndLoadApiHosts();
    if (hosts.length > 0) {
        return hosts[0].value;
    } else {
        saveApiHost(defaultApiHost)
        return defaultApiHost;
    }
};

export {getInitialApiHost, cleanAndLoadApiHosts, saveApiHost}