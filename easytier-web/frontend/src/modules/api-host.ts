// The API base is decided by deployment, not by user input:
// - embedded / same-origin serving: relative requests ('')
// - split deploy with --api-host: injected as window.apiMeta by the server
let apiMeta: {
    api_host: string;
} | undefined = (window as any).apiMeta;

// remove trailing slashes from the URL
const cleanUrl = (url: string) => url.replace(/\/+$/, '');

const getApiBase = (): string => cleanUrl(apiMeta?.api_host ?? '');

export { getApiBase }
