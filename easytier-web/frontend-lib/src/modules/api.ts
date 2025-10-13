import { UUID } from './utils';
import { NetworkConfig } from '../types/network';

export interface ValidateConfigResponse {
    toml_config: string;
}

export interface ListNetworkInstanceIdResponse {
    running_inst_ids: Array<UUID>,
    disabled_inst_ids: Array<UUID>,
}

export interface GenerateConfigResponse {
    toml_config?: string;
    error?: string;
}

export interface ParseConfigResponse {
    config?: NetworkConfig;
    error?: string;
}

export interface RemoteClient {
    validate_config(config: any): Promise<ValidateConfigResponse>;
    run_network(config: any): Promise<undefined>;
    get_network_info(inst_id: string): Promise<any>;
    list_network_instance_ids(): Promise<ListNetworkInstanceIdResponse>;
    delete_network(inst_id: string): Promise<undefined>;
    update_network_instance_state(inst_id: string, disabled: boolean): Promise<undefined>;
    get_network_config(inst_id: string): Promise<any>;
    generate_config(config: NetworkConfig): Promise<GenerateConfigResponse>;
    parse_config(toml_config: string): Promise<ParseConfigResponse>;
}