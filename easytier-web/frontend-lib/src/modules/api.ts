import axios, { AxiosError, AxiosInstance, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import { Md5 } from 'ts-md5'
import { UUID } from './utils';

export interface ValidateConfigResponse {
    toml_config: string;
}

// 定义接口返回的数据结构
export interface LoginResponse {
    success: boolean;
    message: string;
}

export interface RegisterResponse {
    success: boolean;
    message: string;
}

// 定义请求体数据结构
export interface Credential {
    username: string;
    password: string;
}

export interface RegisterData {
    credentials: Credential;
    captcha: string;
}

export interface Summary {
    device_count: number;
}

export interface ListNetworkInstanceIdResponse {
    running_inst_ids: Array<UUID>,
    disabled_inst_ids: Array<UUID>,
}

export class ApiClient {
    private client: AxiosInstance;
    private authFailedCb: Function | undefined;

    constructor(baseUrl: string, authFailedCb: Function | undefined = undefined) {
        this.client = axios.create({
            baseURL: baseUrl + '/api/v1',
            withCredentials: true, // 如果需要支持跨域携带cookie
            headers: {
                'Content-Type': 'application/json',
            },
        });
        this.authFailedCb = authFailedCb;

        // 添加请求拦截器
        this.client.interceptors.request.use((config: InternalAxiosRequestConfig) => {
            return config;
        }, (error: any) => {
            return Promise.reject(error);
        });

        // 添加响应拦截器
        this.client.interceptors.response.use((response: AxiosResponse) => {
            console.debug('Axios Response:', response);
            return response.data; // 假设服务器返回的数据都在data属性中
        }, (error: any) => {
            if (error.response) {
                let response: AxiosResponse = error.response;
                if (response.status == 401 && this.authFailedCb) {
                    console.error('Unauthorized:', response.data);
                    this.authFailedCb();
                } else {
                    // 请求已发出，但是服务器响应的状态码不在2xx范围
                    console.error('Response Error:', error.response.data);
                }
            } else if (error.request) {
                // 请求已发出，但是没有收到响应
                console.error('Request Error:', error.request);
            } else {
                // 发生了一些问题导致请求未发出
                console.error('Error:', error.message);
            }
            return Promise.reject(error);
        });
    }

    // 注册
    public async register(data: RegisterData): Promise<RegisterResponse> {
        try {
            data.credentials.password = Md5.hashStr(data.credentials.password);
            const response = await this.client.post<RegisterResponse>('/auth/register', data);
            console.log("register response:", response);
            return { success: true, message: 'Register success', };
        } catch (error) {
            if (error instanceof AxiosError) {
                return { success: false, message: 'Failed to register, error: ' + JSON.stringify(error.response?.data), };
            }
            return { success: false, message: 'Unknown error, error: ' + error, };
        }
    }

    // 登录
    public async login(data: Credential): Promise<LoginResponse> {
        try {
            data.password = Md5.hashStr(data.password);
            const response = await this.client.post<any>('/auth/login', data);
            console.log("login response:", response);
            return { success: true, message: 'Login success', };
        } catch (error) {
            if (error instanceof AxiosError) {
                if (error.response?.status === 401) {
                    return { success: false, message: 'Invalid username or password', };
                } else {
                    return { success: false, message: 'Unknown error, status code: ' + error.response?.status, };
                }
            }
            return { success: false, message: 'Unknown error, error: ' + error, };
        }
    }

    public async logout() {
        await this.client.get('/auth/logout');
        if (this.authFailedCb) {
            this.authFailedCb();
        }
    }

    public async change_password(new_password: string) {
        await this.client.put('/auth/password', { new_password: Md5.hashStr(new_password) });
    }

    public async check_login_status() {
        try {
            await this.client.get('/auth/check_login_status');
            return true;
        } catch (error) {
            return false;
        }
    }

    public async list_session() {
        const response = await this.client.get('/sessions');
        return response;
    }

    public async list_machines(): Promise<Array<any>> {
        const response = await this.client.get<any, Record<string, Array<any>>>('/machines');
        return response.machines;
    }

    public async list_deivce_instance_ids(machine_id: string): Promise<ListNetworkInstanceIdResponse> {
        const response = await this.client.get<any, ListNetworkInstanceIdResponse>('/machines/' + machine_id + '/networks');
        return response;
    }

    public async update_device_instance_state(machine_id: string, inst_id: string, disabled: boolean): Promise<undefined> {
        await this.client.put<string>('/machines/' + machine_id + '/networks/' + inst_id, {
            disabled: disabled,
        });
    }

    public async get_network_info(machine_id: string, inst_id: string): Promise<any> {
        const response = await this.client.get<any, Record<string, any>>('/machines/' + machine_id + '/networks/info/' + inst_id);
        return response.info.map;
    }

    public async get_network_config(machine_id: string, inst_id: string): Promise<any> {
        const response = await this.client.get<any, Record<string, any>>('/machines/' + machine_id + '/networks/config/' + inst_id);
        return response;
    }

    public async validate_config(machine_id: string, config: any): Promise<ValidateConfigResponse> {
        const response = await this.client.post<any, ValidateConfigResponse>(`/machines/${machine_id}/validate-config`, {
            config: config,
        });
        return response;
    }

    public async run_network(machine_id: string, config: any): Promise<undefined> {
        await this.client.post<string>(`/machines/${machine_id}/networks`, {
            config: config,
        });
    }

    public async delete_network(machine_id: string, inst_id: string): Promise<undefined> {
        await this.client.delete<string>(`/machines/${machine_id}/networks/${inst_id}`);
    }

    public async get_summary(): Promise<Summary> {
        const response = await this.client.get<any, Summary>('/summary');
        return response;
    }

    public captcha_url() {
        return this.client.defaults.baseURL + '/auth/captcha';
    }
}

export default ApiClient;